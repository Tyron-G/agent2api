//! 整库备份 / 恢复：把库拍成一份**一致的快照**，以及把一份快照**安全地换上去**。
//!
//! ── 这一层要解决什么问题 ────────────────────────────────────
//! 旧的「账号导入 / 导出」是按 uid 合并的 JSON 传输，依赖上游提供商的账号
//! 身份结构（UID / userId / apiKey 归一）。反代提供商类型经常变动，那套身份
//! 归一逻辑持续落后于上游、要不断跟改。改成 ccswitch 风格的整库备份 / 恢复后，
//! 本模块**不认识库里的任何业务语义** —— 它只做「拍快照」与「换文件」两件事，
//! 上游怎么变都不用动这份代码。
//!
//! ── 为什么导出不能用「直接拷主库文件」────────────────────────
//! 库跑在 WAL 模式（见 [`super::apply_pragmas`]）：已提交但还没 checkpoint 的
//! 数据**只存在于 `-wal` 里**，直接拷主库会静默丢掉最近若干次写入。所以导出走
//! `PRAGMA wal_checkpoint(TRUNCATE)` + `VACUUM INTO`：后者产出**事务一致的单文件
//! 快照**，且产物**不含 WAL** —— 用户拿到手就是一个能直接打开的 `.db`。
//! （不用 rusqlite 的 `backup` feature：那要给 `rusqlite` 加一个 feature 依赖，
//! 而 `VACUUM INTO` 用现成的 `bundled` SQLite 3.53 就能做，语句形态也与
//! `RequestStats::compact` 的 checkpoint + VACUUM 一脉相承。）
//!
//! ── 为什么恢复必须在**任何库访问之前** ───────────────────────
//! Windows 无法替换（甚至无法删除）一个被打开的文件。所以替换只能发生在启动
//! 流程里、**还没有任何代码打开过这个库**的那一刻。两个入口各钉一次：
//!   - 桌面壳：`lib.rs` 的 `migrate_config_dir()` 之后、`settings::load()` 之前
//!     （后者经 `settings::sql` 的短命连接直读同一个库，是第一处库访问）；
//!   - headless：`bin/agent2api-server.rs` 的 `ServerState::bootstrap` 之前。
//! 晚于这两处，`rename` 就会因文件锁失败。这是本模块唯一的时序要求。
//!
//! ── 恢复的失败为什么**不该**让程序起不来 ─────────────────────
//! 关键事实：**换库是「先拷副本、最后原子 rename」，任何一步失败主库都原封不动**
//! （rename 是最后一步，且 Windows 上走 `MoveFileExW(REPLACE_EXISTING)`，要么
//! 换成、要么没换）。既然主库永远安全，就没必要用「起不来」去惩罚用户 ——
//! 那只会让一次手滑选错文件变成「程序打不开」。所以本模块的失败语义是：
//! **返回 `Err` 供调用方记日志 / 弹提示，但调用方应当照常启动**，用户看到的是
//! 「旧数据还在 + 一句说清为什么没恢复」。校验不过的 pending 直接删掉
//! （用户手上那份原始备份文件始终没被动过），替换失败的 pending 留着下次重试。
//!
//! ⚠️ 上面那句「任何一步失败主库都原封不动」**不是白来的**，它有一个前提：
//! **第 2 步必须先把 `-wal` 并干净**。因为第 4 步会无条件删 `-wal`、而第 3 步的
//! 副本不含它，若带着没并干净的 `-wal` 往下走，一旦第 5 步 rename 失败，主库
//! 就会丢掉已提交的尾巴。所以第 2 步**并不动就整个放弃**（见 [`drain_wal`]）——
//! 那是维持这条承诺的必要条件，不是可以省掉的优化。
//!
//! ```text
//! db/
//!   mod.rs     连接与句柄（Db::open / with / with_mut / file）
//!   schema.rs  全部建表 DDL 与版本管理（PRAGMA user_version 逐版本升级）
//!   migrate/   旧文件 → 数据库的一次性迁移
//!   restore.rs 整库备份 / 恢复（本文件）
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use super::schema;
use super::Db;

/// 待恢复的备份文件：用户选定的备份先落到这个文件名，重启后由
/// [`apply_pending`] 在启动期换上去。
///
/// 为什么是「先落盘、重启再换」而不是当场就换：进程跑着的时候库是打开的，
/// 换不了（见模块头的时序说明）。这个文件名本身就是「有一份备份等着被应用」
/// 这个状态的载体 —— 它存在即待办，应用完即消失，不需要额外的标记文件。
pub const PENDING_FILE: &str = "agent2api.db.restore-pending";

/// 恢复前自动留下的**旧库副本**（回滚路径）。
///
/// 为什么要有它：换库是整文件替换，一旦换上一个坏的备份，用户原来那份数据就
/// 没了。留一份副本，最坏情况也能手工把文件名换回去。只保留**一份**（同名覆盖），
/// 不做历史轮转 —— 多份副本在库几百 MB 时是实打实的双倍磁盘占用，而它的定位
/// 只是「这一次恢复的回滚点」，不是备份归档（备份归档是用户自己导出的事）。
pub const SAFETY_FILE: &str = "agent2api.db.pre-restore";

/// SQLite 库文件头的 16 字节魔数。桌面壳没有 rusqlite，只能查这个做即时校验；
/// 这里也用同一判据做第一道粗筛（比打开库便宜）。
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// 「这是一个 Agent2API 库」的**最小签名**：v1 建的表里抽三张核心表。
///
/// ── 为什么需要这道校验 ────────────────────────────────────────
/// 光验「是 SQLite + `quick_check` 通过 + 版本不超前」挡不住**另一个程序的
/// 合法库** —— 最现实的就是 cc-switch 自己的备份（用户完全可能按这个功能的
/// 心智模型拿错），它同样是完好的 `.db`、`user_version` 同样是 0。放它进去的
/// 后果是**静默毁掉用户数据**：`user_version=0` → 启动时 `schema::migrate`
/// 从 v1 跑起，而 v1 的建表全是 `CREATE TABLE IF NOT EXISTS`，于是它「就地
/// 补建」出一套空表 —— 主库被换成了本程序的空库，旧数据只剩 `pre-restore`。
/// 更糟的是若那个库里有同名表（如 `accounts`），v2 起的裸 `ALTER` 会撞名，
/// 启动直接失败。所以**必须在替换前认出「这不是我们的库」**。
///
/// ── 为什么是「表存在」而不是版本号 ────────────────────────────
/// 不能要求 `user_version` 落在某个区间：v1 时代的合法老备份 `user_version`
/// 就是 1，而「空库」与「真 v1 库」在版本号上无法区分，只能看表。
/// 也不能靠新增一个标记键（往 `kv` 里写一行身份）—— 那对**已存在的**合法老库
/// 是缺失的，会把用户自己的老备份判死，代价远大于收益。
///
/// ── 为什么这三张表是安全的判据 ────────────────────────────────
/// 已核实 `schema.rs` 与 `migrate/` 全库**没有任何 `DROP TABLE`** —— 表集只增
/// 不减。所以这三张 v1 的表在**任何版本**的合法库里都必然存在：老库有（v1 建的），
/// 新库也有（只增不减）。反过来，任何别的程序都不太可能同时有 `accounts`、
/// `logs`、`requests` 这三张同名的表。
///
/// 不用 `kv` 当判据：它太通用（「key/value」是常见命名），误判率高于上面三张。
const REQUIRED_TABLES: [&str; 3] = ["accounts", "logs", "requests"];

/// 临时快照的存活上限：超过它就被 [`sweep_stale_snapshots`] 清掉。
///
/// 定位是「进程在导出途中被杀掉留下的孤儿文件」。一小时远大于任何一次正常
/// 导出（几百 MB 的库也就几秒），又远小于「用户下次启动」的间隔，不会误删
/// 正在用的快照。
const STALE_SNAPSHOT_AGE: Duration = Duration::from_secs(60 * 60);

/// 临时快照的文件名前缀（`{prefix}{pid}-{nanos}.db`）。
const SNAPSHOT_PREFIX: &str = "agent2api-backup-";

/// [`apply_pending`] 的结果。
#[derive(Debug)]
pub enum RestoreOutcome {
    /// 没有待恢复的备份（绝大多数启动走这条）
    NothingToDo,
    /// 已换上备份，`safety` 是替换前那份旧库的副本路径
    Applied { safety: PathBuf },
}

/// 把当前库拍成一份**事务一致的单文件快照**，返回临时文件路径。
///
/// 调用方负责在用完之后删掉它（导出接口是「发完流就删」，见 `api::db_api`）。
/// 失败时把 rusqlite 的错误原文带出去 —— 「database or disk is full」这类是
/// 可读的，包成笼统的「导出失败」反而让用户没法自助（VACUUM INTO 需要约等于
/// 库大小的**额外空闲磁盘**，这是最常见的失败原因）。
///
/// ── 为什么持锁 ──────────────────────────────────────────────
/// 与 `RequestStats::compact` 同一条理由：本项目是「同步 rusqlite 单连接 +
/// 一把 Mutex」，`VACUUM INTO` 必须与其它读写互斥，唯一正确的入口就是
/// `Db::with`（拿锁）。持锁期间其余访问排队；几百 MB 的库也就秒级。
///
/// ── 目标文件必须不存在 ──────────────────────────────────────
/// `VACUUM INTO` 拒绝已存在的目标（它不会覆盖）。所以名字带 pid + 纳秒，
/// 保证唯一 —— 与 `test_temp::TempDb` 的命名手法同源。
pub fn snapshot_to_temp(db: &Db) -> Result<PathBuf, String> {
    let target = unique_snapshot_path();
    // 双保险：万一纳秒撞了（不可能，但便宜），先清掉
    let _ = std::fs::remove_file(&target);

    let literal = sql_string_literal(&target);
    let outcome = db.with(|conn| -> rusqlite::Result<()> {
        // 先把 WAL 并回主库：不是 VACUUM INTO 的要求（它读的是事务快照），
        // 而是让「导出完成」这一刻磁盘上没有未合并的尾巴 —— 用户如果顺手去
        // 拷主库文件，拿到的是完整数据。
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        conn.execute_batch(&format!("VACUUM INTO {literal};"))?;
        Ok(())
    });

    match outcome {
        // 库不可用（打开失败 / 锁中毒）：如实说，别让用户以为是磁盘问题
        None => Err("数据库不可用，无法导出备份".to_string()),
        Some(Ok(())) => Ok(target),
        Some(Err(error)) => {
            // 失败时把半截产物清掉，别在 temp 里留垃圾
            let _ = std::fs::remove_file(&target);
            Err(format!("生成备份快照失败: {error}"))
        }
    }
}

/// 启动期应用待恢复的备份（用 `config::config_dir()`）。
///
/// **必须在任何数据库访问之前调用** —— 见模块头的时序说明。
/// 顺带清理 [`sweep_stale_snapshots`]（这里本来就是启动期，顺手做掉）。
///
/// 失败返回 `Err` 供调用方记日志 / 提示，**调用方应当照常启动**（理由见模块头）。
pub fn apply_pending() -> Result<RestoreOutcome, String> {
    sweep_stale_snapshots();
    apply_at(&crate::server::config::config_dir())
}

/// [`apply_pending`] 的可测版本：显式传入配置目录。
pub(crate) fn apply_at(dir: &Path) -> Result<RestoreOutcome, String> {
    let pending = dir.join(PENDING_FILE);
    if !pending.exists() {
        return Ok(RestoreOutcome::NothingToDo);
    }
    let main = dir.join(super::FILE_NAME);
    let safety = dir.join(SAFETY_FILE);

    // ── 第 1 步：校验 ────────────────────────────────────────
    // 不过就删掉 pending 并返回 Err。删掉而不是留着重试：坏文件重启一百次
    // 还是坏的，留着只会让每次启动都报同一条错。**用户手上那份原始备份文件
    // 始终没被动过**（我们是 copy 进来的，不是 move），所以他没丢东西。
    if let Err(reason) = validate_upload(&pending) {
        let _ = std::fs::remove_file(&pending);
        return Err(format!("备份文件不可用，已忽略（{reason}）"));
    }

    // ── 第 2 步：把旧库的 WAL 并回去（**并不动就整个放弃**）────────
    // 用**短命连接**：它只活这一次 checkpoint，用完即关（关掉才轮到我们动文件）。
    // 这一步失败必须**阻断**整个恢复，不能 best-effort —— 理由见 `drain_wal`：
    // 并不动就意味着第 4 步要删的 `-wal` 里还压着用户已提交的数据。
    if main.exists() {
        drain_wal(&main)?;
    }

    // ── 第 3 步：留旧库副本 ───────────────────────────────────
    // **copy 而不是 rename**：主库全程存在，没有「主库短暂消失」的窗口 ——
    // 这正是与 `config_migration` 的「绝不覆盖」相反的取舍（那边是新建目标，
    // 这边就是要覆盖）。
    if main.exists() {
        std::fs::copy(&main, &safety).map_err(|error| {
            format!("无法保留旧库副本（{}）：{error}", safety.display())
        })?;
    }

    // ── 第 4 步：清掉属于旧库的 sidecar ───────────────────────
    // `-wal` / `-shm` 与主库是一体的，留给新库就是「新库 + 旧库的 WAL」，
    // SQLite 打开时会按旧 WAL 的页号去改新库 —— 那是数据损坏，不是小毛病。
    // 校验时打开过 pending，它旁边也可能被建了 sidecar，一并清掉。
    for path in [
        sidecar(&main, "-wal"),
        sidecar(&main, "-shm"),
        sidecar(&pending, "-wal"),
        sidecar(&pending, "-shm"),
    ] {
        let _ = std::fs::remove_file(path);
    }

    // ── 第 5 步：原子换上 ─────────────────────────────────────
    // Windows 上 Rust 的 rename 走 MoveFileExW(MOVEFILE_REPLACE_EXISTING)：
    // 要么换成、要么没换，不存在「主库被删了但新的没到位」的中间态。
    // 失败（典型是旧进程还没退干净、文件仍被锁）→ pending 留着，下次启动
    // 重试；主库与副本都完好。
    std::fs::rename(&pending, &main)
        .map_err(|error| format!("替换数据库文件失败（{error}）；备份已保留，下次启动会自动重试"))?;

    Ok(RestoreOutcome::Applied { safety })
}

/// 把主库旁边 `-wal` 里**已提交但还没并回主库**的事务并进去，并确认真的并干净了。
///
/// ── 为什么这一步不能 best-effort ──────────────────────────────
/// 第 4 步会**无条件删掉** `-wal`，而第 3 步的 `fs::copy` 只拷主库文件、**不含
/// `-wal` 里的内容**。所以只要这里没并干净，用户最近提交的数据就只存在于那个
/// 即将被删掉的 `-wal` 里。正常路径上第 5 步的 `rename` 会把它一并换掉（旧库
/// 连 WAL 一起消失，本来就要消失），但 `rename` 是**可能失败的**（Windows 上
/// 旧进程占着文件是典型原因，见第 5 步注释）。那时主库文件名还是旧的、内容却
/// 已经丢了尾巴 —— 既不是旧的也不是新的，而用户看到的是「恢复失败、旧数据还在」。
/// 这正对着模块头承诺的「任何一步失败主库都原封不动」。
///
/// ── 为什么不能只看语句有没有报错 ──────────────────────────────
/// `PRAGMA wal_checkpoint(TRUNCATE)` 拿不到锁时**不报错**，只在返回行里给
/// `busy=1`（实测：持锁时返回 `{busy:1,...}`，语句本身 `Ok`）。所以
/// `execute_batch` 成功**不等于**并干净了 —— 必须把那一行读出来。
/// 判据只看第 1 列：后两列（`log` / `checkpointed`）随当时有没有待并的帧而变，
/// 不作判据（非 WAL 库上是 `-1`，WAL 库上可能是 `0` 也可能是正数）。
fn drain_wal(main: &Path) -> Result<(), String> {
    let merged = Connection::open(main)
        .and_then(|conn| {
            // 第 1 列就是 busy 标志。用 query_row 而不是 execute_batch：
            // 后者把结果行丢掉，正是看不见 busy 的原因。
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |row| {
                row.get::<_, i64>(0)
            })
        })
        .map(|busy| busy == 0)
        // 连打开都失败（库被独占、权限、损坏）：同样当作「没并干净」处理，
        // 不能因为「读不到 busy」就默认成功。
        .unwrap_or(false);

    if merged {
        return Ok(());
    }
    Err(
        "旧数据库的写入日志（-wal）没能并回主库，已放弃本次恢复以免丢失最近的数据。\
         请确认没有另一个实例（例如 Docker 容器、或上一个还没退干净的进程）\
         正在使用同一个数据目录，关闭它之后重试。\
         主库与你的备份文件都未被改动。"
            .to_string(),
    )
}

/// 「同一时刻只有一次恢复在写 [`PENDING_FILE`]」的守卫（RAII：出作用域即释放）。
///
/// ── 为什么必须共享，而不是各入口自己防 ────────────────────────
/// `PENDING_FILE` 是**一个固定路径**，而写它的入口有**两个**、跑在**同一个进程**
/// 里：网页端的 `POST /api/db/restore`（HTTP 上传）与桌面端的 `restore_database`
/// 命令（本地文件直接拷）。两边都会先 `remove_file` 再建文件写 —— 交错执行就是
/// 「后到的截断前一个」，留下半截 pending，而两个入口各自已经回了话（一个说
/// 「正在重启」、一个说别的），语义全乱；下次启动还会把半截文件当备份去换库。
/// 守卫是进程级的 `static`，所以**两个入口共用同一把**才算真的挡住了。
/// 放在本模块而不是 HTTP 层：不变量属于「谁拥有 PENDING_FILE」，不属于调用方。
///
/// 用 `AtomicBool::compare_exchange` 而不是 `Mutex`：要的是「抢到就干活、抢不到
/// 立刻拒绝」，不是「排队等」；`try_lock` 语义用 CAS 最直白。HTTP 侧的 handler
/// 全程有 `.await`，持锁跨 await 会拖死并发 —— CAS 不持有任何跨 await 的东西。
///
/// 进程重启后标志自然归零 —— 恢复本来就是「写完 pending 就退出」，
/// 不需要跨进程的持久化互斥。
static RESTORE_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// [`RESTORE_IN_FLIGHT`] 的 RAII 句柄：析构即释放。
pub struct RestoreGuard;

impl RestoreGuard {
    /// 抢到返回 `Some`，已被占用返回 `None`（调用方应当直接拒绝，让用户重试）。
    pub fn acquire() -> Option<Self> {
        use std::sync::atomic::Ordering;
        RESTORE_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        RESTORE_IN_FLIGHT.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// 校验一份待恢复的文件是不是**能用**的 SQLite 库。
///
/// 三道，都便宜：
///   1. 16 字节文件头必须是 `SQLite format 3\0`；
///   2. `PRAGMA quick_check` —— 比 `integrity_check` 便宜得多，仍能抓住结构性
///      损坏；
///   3. 必须含 [`REQUIRED_TABLES`] 那几张核心表 —— 认出「这不是本程序的库」，
///      挡住「拿 cc-switch 的备份来恢复」这类**会静默清空数据**的错误。
///
/// ── 第 2 道为什么是必须的 ────────────────────────────────────
/// `schema::migrate` **只升不降**（版本已达标就直接返回，见那边的注释）。
/// 于是恢复一份**更新**版本程序产出的备份时，它不会报错、也不会降级 ——
/// 会拿着新 schema 的表结构按旧代码去读写，行为未定义（缺列、语义错位，
/// 且可能静默写坏数据）。这类错误必须在这里挡住，不能留给运行期。
/// 反过来，恢复**更旧**的备份是安全的：启动时 migrate 会把它升到当前版本。
///
/// `pub(crate)` 供 `api::db_api` 的上传接口复用 —— 那份文件在**收到时**就该
/// 被拒，而不是等用户重启一次才发现选错了文件。启动期的 [`apply_at`] 仍会
/// 再校验一次（两次之间文件仍可能被外部改动，那是替换前的最后一道闸）。
pub(crate) fn validate_upload(path: &Path) -> Result<(), String> {
    // 第一道粗筛：文件头。比打开库便宜，且对「用户选了个 .jpg」这类最常见
    // 的错误给出最直白的答复。
    let header = read_header(path)?;
    if &header != SQLITE_MAGIC {
        return Err("不是有效的 SQLite 数据库文件".to_string());
    }

    // 必须用**裸连接**而不是 `Db::open`：后者会跑 `apply_pragmas` 与
    // `schema::migrate`，**会写这个文件** —— 那会把「待恢复的备份」改掉，
    // 而且改的正是我们要据以判断的 user_version。
    let conn = Connection::open(path)
        .map_err(|error| format!("打开备份文件失败: {error}"))?;

    let check: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|error| format!("备份文件无法读取: {error}"))?;
    if check != "ok" {
        return Err(format!("备份文件已损坏（{check}）"));
    }

    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| format!("读取备份文件版本失败: {error}"))?;
    if version > schema::SCHEMA_VERSION {
        return Err(format!(
            "该备份来自更新的版本（数据版本 v{version}，本程序最高支持 v{}）：请先升级程序再恢复",
            schema::SCHEMA_VERSION
        ));
    }

    // 第三道：确认它**是本程序的库**，而不是随便一个合法的 SQLite 文件。
    // 放在版本判断之后 —— 版本超前是最明确的「你拿错东西了」，先报那一条。
    for table in REQUIRED_TABLES {
        let present: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .map_err(|error| format!("读取备份文件结构失败: {error}"))?;
        if present == 0 {
            return Err(
                "该文件不是 Agent2API 的数据库备份（缺少核心数据表）：请选择由本程序导出的 .db 备份"
                    .to_string(),
            );
        }
    }

    Ok(())
}

/// 读文件前 16 字节。文件太短（连文件头都不够）按「不是 SQLite 文件」处理。
fn read_header(path: &Path) -> Result<[u8; 16], String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("无法读取备份文件: {error}"))?;
    let mut header = [0u8; 16];
    file.read_exact(&mut header)
        .map_err(|_| "不是有效的 SQLite 数据库文件（文件过短）".to_string())?;
    Ok(header)
}

/// 清理 `temp_dir` 下超龄的导出快照（进程在导出途中被杀掉留下的孤儿）。
///
/// best-effort：读不到目录、删不掉文件都不报错 —— 这是顺手做的卫生，
/// 不是启动的必要条件，绝不能因为它让启动失败。
pub fn sweep_stale_snapshots() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(SNAPSHOT_PREFIX) || !name.ends_with(".db") {
            continue;
        }
        // 按修改时间判龄：读不到元数据就跳过（不猜）
        let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) else {
            continue;
        };
        let Ok(age) = now.duration_since(modified) else {
            continue; // 时钟回拨：宁可留着也不误删
        };
        if age > STALE_SNAPSHOT_AGE {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// 唯一的快照路径（`{temp}/agent2api-backup-{pid}-{nanos}.db`）。
fn unique_snapshot_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{SNAPSHOT_PREFIX}{}-{nanos}.db", std::process::id()))
}

/// 把路径转成 SQL 字符串字面量（含引号）。
///
/// `VACUUM INTO` **不支持参数绑定**（它要的是「一个文件名」，不是「一个值」），
/// 只能拼进 SQL 串。所以单引号必须按 SQL 规则转义成两个；反斜杠在 SQLite 的
/// 字符串字面量里没有特殊含义，Windows 路径可以原样放（这也是为什么不加
/// `ESCAPE` 子句、不碰 `\` 的原因 —— 多转义一次反而会拼出错的路径）。
fn sql_string_literal(path: &Path) -> String {
    let text = path.to_string_lossy();
    format!("'{}'", text.replace('\'', "''"))
}

/// 主库旁边的 sidecar 路径（`-wal` / `-shm`）。
fn sidecar(base: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", base.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::db::test_temp::TempDir;

    /// 在 `dir` 下造一个「能认出来是哪个库」的最小 SQLite 库：
    /// 写一行标记到 `kv` 表，读回来就能知道当前主库是 A 还是 B。
    ///
    /// 同时把 [`REQUIRED_TABLES`] 那几张表也建出来 —— 校验要求「看得出是本程序
    /// 的库」，夹具必须造出这个形状，否则合法库会被自己的校验判死。
    fn make_db(path: &Path, marker: &str) {
        let conn = Connection::open(path).expect("建库失败");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY);",
        )
        .expect("建表失败");
        conn.execute(
            "INSERT INTO kv (key, value) VALUES ('marker', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [marker],
        )
        .expect("写标记失败");
        conn.execute_batch(&format!("PRAGMA user_version = {};", schema::SCHEMA_VERSION))
            .expect("写版本失败");
    }

    /// 读回标记；库打不开或没有标记都返回 None。
    fn read_marker(path: &Path) -> Option<String> {
        let conn = Connection::open(path).ok()?;
        conn.query_row("SELECT value FROM kv WHERE key = 'marker'", [], |row| row.get(0)).ok()
    }

    #[test]
    fn pending_is_applied() {
        let dir = TempDir::new("restore-apply");
        let main = dir.path().join(super::super::FILE_NAME);
        let pending = dir.path().join(PENDING_FILE);
        let safety = dir.path().join(SAFETY_FILE);

        make_db(&main, "旧库");
        make_db(&pending, "新库");
        // 旧库的 sidecar：换库后必须消失，否则新库会按旧 WAL 的页号被改写
        std::fs::write(sidecar(&main, "-wal"), b"stale-wal").unwrap();
        std::fs::write(sidecar(&main, "-shm"), b"stale-shm").unwrap();

        let outcome = apply_at(dir.path()).expect("应用备份应当成功");
        assert!(matches!(outcome, RestoreOutcome::Applied { .. }), "应报 Applied");

        assert_eq!(read_marker(&main).as_deref(), Some("新库"), "主库应换成备份内容");
        assert_eq!(read_marker(&safety).as_deref(), Some("旧库"), "副本应是替换前的旧库");
        assert!(!pending.exists(), "pending 应用后应消失");
        assert!(!sidecar(&main, "-wal").exists(), "旧库的 -wal 应被清掉");
        assert!(!sidecar(&main, "-shm").exists(), "旧库的 -shm 应被清掉");
    }

    /// **WAL 并不干净时必须整个放弃** —— 这是本模块最隐蔽的一条。
    ///
    /// 复现的是「另一个实例（Docker 容器 / 没退干净的旧进程）还占着这个库」：
    /// 第 2 步的 checkpoint 拿不到写锁。此时若照旧往下走，第 4 步会**无条件删掉**
    /// `-wal`，而第 3 步的副本只拷主库文件、不含 `-wal` 里的已提交事务 ——
    /// 一旦第 5 步 rename 也失败（旧进程占着文件，正是同一原因），主库就变成
    /// 「文件名是旧的、最近的事务已经没了」，而用户看到的是「恢复失败、旧数据还在」。
    ///
    /// `PRAGMA wal_checkpoint(TRUNCATE)` 拿不到锁时**不报错**，只在返回行里给
    /// `busy=1`（实测：持写锁时返回 `{busy:1,...}`，语句本身 `Ok`）。所以这条
    /// 路径靠「语句有没有报错」是**看不见**的 —— 本用例正是钉住这一点。
    #[test]
    fn aborts_when_wal_cannot_be_drained() {
        let dir = TempDir::new("restore-wal-busy");
        let main = dir.path().join(super::super::FILE_NAME);
        let pending = dir.path().join(PENDING_FILE);
        make_db(&main, "旧库");
        make_db(&pending, "新库");

        // 把主库切成 WAL 模式并留下真实的 `-wal`（make_db 的裸连接是默认
        // journal 模式，没有 sidecar —— 那测不出这一步）。
        {
            let conn = Connection::open(&main).unwrap();
            conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        }

        // 另一个连接持写锁：checkpoint 会拿到 busy=1
        let holder = Connection::open(&main).expect("持锁连接应能打开");
        holder.execute_batch("BEGIN IMMEDIATE;").unwrap();
        holder
            .execute("INSERT OR REPLACE INTO kv (key, value) VALUES ('held', '未提交')", [])
            .unwrap();

        let error = apply_at(dir.path()).expect_err("WAL 并不干净时必须放弃本次恢复");
        assert!(error.contains("并回主库"), "文案应说清是 WAL 没并回去：{error}");

        // 主库原封不动 —— 这正是模块头那句承诺的兑现
        drop(holder); // 先放锁，否则下面读库可能拿不到
        assert_eq!(read_marker(&main).as_deref(), Some("旧库"), "主库必须原封不动");
        assert!(!dir.path().join(SAFETY_FILE).exists(), "没走到留副本那步，不该有副本");
        // 关键：pending **保留**（与「校验不过就删」不同）—— 这是可重试的
        // 环境问题，用户关掉那个实例后重启一次就能成
        assert!(pending.exists(), "环境原因失败时 pending 应保留，供下次启动重试");
    }

    #[test]
    fn nothing_to_do_without_pending() {
        let dir = TempDir::new("restore-none");
        let main = dir.path().join(super::super::FILE_NAME);
        make_db(&main, "旧库");

        let outcome = apply_at(dir.path()).expect("没有 pending 不算失败");
        assert!(matches!(outcome, RestoreOutcome::NothingToDo));
        assert_eq!(read_marker(&main).as_deref(), Some("旧库"), "主库不该被动过");
        assert!(!dir.path().join(SAFETY_FILE).exists(), "没恢复就不该留副本");
    }

    #[test]
    fn rejects_newer_schema() {
        let dir = TempDir::new("restore-newer");
        let main = dir.path().join(super::super::FILE_NAME);
        let pending = dir.path().join(PENDING_FILE);
        make_db(&main, "旧库");
        make_db(&pending, "新库");
        // 伪造一份「来自更新版本程序」的备份
        Connection::open(&pending)
            .unwrap()
            .execute_batch(&format!("PRAGMA user_version = {};", schema::SCHEMA_VERSION + 1))
            .unwrap();

        let error = apply_at(dir.path()).expect_err("更新的 schema 必须被拒");
        assert!(error.contains("更新的版本"), "文案应说清是版本太新：{error}");
        assert_eq!(read_marker(&main).as_deref(), Some("旧库"), "主库必须原封不动");
        assert!(!pending.exists(), "被拒的 pending 应清掉（坏文件重启一百次还是坏的）");
    }

    #[test]
    fn rejects_corrupt_pending() {
        let dir = TempDir::new("restore-corrupt");
        let main = dir.path().join(super::super::FILE_NAME);
        let pending = dir.path().join(PENDING_FILE);
        make_db(&main, "旧库");
        // 有合法的文件头（骗过第一道粗筛），但内容全是垃圾
        let mut bytes = SQLITE_MAGIC.to_vec();
        bytes.extend_from_slice(&[0xAAu8; 4096]);
        std::fs::write(&pending, &bytes).unwrap();

        let error = apply_at(dir.path()).expect_err("损坏的备份必须被拒");
        assert!(
            error.contains("无法读取") || error.contains("损坏"),
            "文案应指向文件损坏：{error}"
        );
        assert_eq!(read_marker(&main).as_deref(), Some("旧库"), "主库必须原封不动");
        assert!(!pending.exists(), "被拒的 pending 应清掉");
    }

    #[test]
    fn rejects_non_sqlite_file() {
        let dir = TempDir::new("restore-notdb");
        let main = dir.path().join(super::super::FILE_NAME);
        make_db(&main, "旧库");
        // 用户手滑选了个 .jpg
        std::fs::write(dir.path().join(PENDING_FILE), b"\xff\xd8\xff\xe0 not a database").unwrap();

        let error = apply_at(dir.path()).expect_err("非 SQLite 文件必须被拒");
        assert!(error.contains("不是有效的 SQLite"), "文案应直说不是 SQLite：{error}");
        assert_eq!(read_marker(&main).as_deref(), Some("旧库"), "主库必须原封不动");
    }

    /// 另一个程序的**合法** SQLite 库（最现实的是 cc-switch 自己的备份）必须被拒。
    ///
    /// 这是本模块最要命的一条：不挡的话，`user_version=0` 会让启动期的 migrate
    /// 从 v1 跑起，而 v1 全是 `CREATE TABLE IF NOT EXISTS` —— 它「就地补建」出
    /// 一套空表，主库被换成空库，用户的账号/日志/统计**静默消失**。
    #[test]
    fn rejects_foreign_sqlite_database() {
        let dir = TempDir::new("restore-foreign");
        let main = dir.path().join(super::super::FILE_NAME);
        let pending = dir.path().join(PENDING_FILE);
        make_db(&main, "旧库");

        // 一个完好的库：quick_check 通过、user_version 是 0（新库的默认值），
        // 但表集与本程序无关 —— 正是 cc-switch 备份的样子。
        let conn = Connection::open(&pending).expect("建外部库失败");
        conn.execute_batch("CREATE TABLE conversations (id TEXT PRIMARY KEY, title TEXT);")
            .expect("建表失败");
        drop(conn);

        let error = apply_at(dir.path()).expect_err("外部程序的库必须被拒");
        assert!(
            error.contains("不是 Agent2API 的数据库备份"),
            "文案应直说不是本程序的备份：{error}"
        );
        assert_eq!(read_marker(&main).as_deref(), Some("旧库"), "主库必须原封不动");
        assert!(!pending.exists(), "被拒的 pending 应清掉");
    }

    /// 合法库的表集校验不能误杀**老版本**的备份：v1 时代只有这几张表、
    /// 后面版本加的表一个都没有，也必须放行（表集只增不减）。
    #[test]
    fn accepts_older_backup_with_only_v1_tables() {
        let dir = TempDir::new("restore-old");
        let pending = dir.path().join(PENDING_FILE);
        make_db(&pending, "老备份");
        // 降到 v1：模拟旧版本程序导出的备份
        Connection::open(&pending)
            .unwrap()
            .execute_batch("PRAGMA user_version = 1;")
            .unwrap();

        validate_upload(&pending).expect("只有 v1 表的合法老备份必须通过校验");
    }

    #[test]
    fn snapshot_is_a_valid_database() {
        let (db, _guard) = crate::server::db::test_temp::TempDb::open("restore-snapshot");
        db.with(|conn| {
            conn.execute_batch("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
                .unwrap();
            conn.execute("INSERT INTO kv (key, value) VALUES ('marker', '原库')", []).unwrap();
        })
        .expect("库应当可用");

        let snapshot = snapshot_to_temp(&db).expect("拍快照应当成功");
        // 用守卫保证任何断言失败都不会把临时文件留在 temp 里
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _cleanup = Cleanup(snapshot.clone());

        // 是个能打开、结构完好、数据在的库
        let conn = Connection::open(&snapshot).expect("快照应当能打开");
        let check: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0)).unwrap();
        assert_eq!(check, "ok");
        let marker: String = conn
            .query_row("SELECT value FROM kv WHERE key = 'marker'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(marker, "原库", "快照应含源库数据");
        drop(conn);

        // 关键：**没有 -wal 伴随** —— 证明它是自足的单文件快照，
        // 用户拷走这一个文件就是完整数据
        assert!(!sidecar(&snapshot, "-wal").exists(), "快照不应带 -wal");
    }

    #[test]
    fn sql_literal_escapes_quotes() {
        assert_eq!(sql_string_literal(Path::new("/tmp/a'b.db")), "'/tmp/a''b.db'");
        // Windows 路径的反斜杠原样保留（SQLite 字符串里无特殊含义）
        assert_eq!(sql_string_literal(Path::new(r"C:\x\y.db")), r"'C:\x\y.db'");
    }
}
