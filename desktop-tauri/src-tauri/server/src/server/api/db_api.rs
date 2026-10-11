//! 整库备份 / 恢复的两条接口（替换旧的账号导入导出）。
//!
//! ```text
//! GET  /api/db/backup   导出：VACUUM INTO 快照 → 裸文件附件响应
//! POST /api/db/restore  恢复（网页端）：请求体流式落盘 → 校验 → 重启进程
//! ```
//!
//! ── 为什么导出走**响应体**而恢复走**请求体** ──────────────────
//! 面板路由的请求体上限是 `http::MAX_BODY_SIZE`（32MB），而库可达数百 MB
//! （`request_raw` 一张表就能到 512MB）—— 所以**恢复**这条路由必须单独放宽
//! 上限（`DefaultBodyLimit` 是按路由层叠的，见 `http::router` 的说明），
//! 并且**流式落盘**（不能 `to_bytes()` 把整库读进内存）。
//! 导出方向没有这个约束：响应体不受 `DefaultBodyLimit` 管，直接流式发即可。
//!
//! ── 为什么挂 `protected` ─────────────────────────────────────
//! 备份文件里有**全部账号凭证 + 面板管理员 bcrypt 哈希 + 网关 Key + ALTCHA
//! 密钥**，比旧的账号导出敏感得多。与 `/api/storage`（只读概况）同级，
//! 一律要鉴权。

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::io::AsyncWriteExt;

use crate::server::db::restore;
use crate::server::errors::management_error;
use crate::server::http::raw_json;
use crate::server::logging;
use crate::server::ServerState;

/// 恢复上传的大小上限：2GB。
///
/// 比库的现实体积宽裕得多（最大的表 `request_raw` 上限约 512MB），但**必须有
/// 一个上限** —— 这是对外可达的写盘接口，无上限等于给任何人一个「把磁盘写满」
/// 的入口。2GB 既容得下任何正常备份，又让恶意请求撞墙而不是撞爆磁盘。
const RESTORE_MAX_BODY: usize = 2 * 1024 * 1024 * 1024;

/// 给恢复路由用的 body 上限层（在 `http::router` 里逐路由挂上）。
pub fn restore_body_limit() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(RESTORE_MAX_BODY)
}

/// GET /api/db/backup —— 导出整库为单个 `.db` 附件。
///
/// 形态照 `api::logs_api::download_logs`：**裸文件响应**，不套
/// `{success, data}` 信封（载荷不是 JSON，套了反而要前端再剥一层）。
///
/// 快照在 `spawn_blocking` 里做：`Db::with` 是**阻塞**调用（拿锁会等），
/// 放进异步任务会占死一个 tokio worker 线程。这里用 `spawn_blocking` 而不是
/// `RequestStats::compact` 那种 `std::thread::spawn`：那边是「后台跑完即弃」，
/// 这里**要等结果才能发响应**，需要一个能 await 的句柄。
pub async fn backup_database(State(state): State<ServerState>) -> Response {
    let Some(db) = state.db().cloned() else {
        return management_error(503, "数据库不可用，无法导出备份");
    };

    let snapshot = match tokio::task::spawn_blocking(move || restore::snapshot_to_temp(&db)).await {
        Ok(Ok(path)) => path,
        // 快照失败的原因原样透出：`VACUUM INTO` 最常见的失败是磁盘空间不足，
        // 它的错误文案（"database or disk is full"）是可读的，包成笼统的
        // 「导出失败」反而让用户没法自助。
        Ok(Err(error)) => {
            logging::log("[Backup]", &format!("❌ 导出备份失败: {error}"));
            return management_error(500, error);
        }
        Err(error) => {
            logging::log("[Backup]", &format!("❌ 导出备份任务异常: {error}"));
            return management_error(500, "导出备份失败");
        }
    };

    stream_snapshot(snapshot).await
}

/// 把快照文件流式发出去，并在**流结束或客户端中断**时删掉它。
///
/// 用 `ReaderStream`（64KB 分块）而不是 `tokio::fs::read`：几百 MB 的库整份
/// 进内存是不可接受的。
///
/// 临时文件的清理挂在 [`SnapshotGuard`] 的 `Drop` 上，由流闭包捕获 ——
/// 流被丢弃（正常发完 / 客户端断开 / 响应被取消）时守卫析构、文件删除。
/// 这比「发完之后手动删」可靠：手动删漏掉任何一条提前返回的路径就会留垃圾。
async fn stream_snapshot(path: std::path::PathBuf) -> Response {
    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(error) => {
            logging::log("[Backup]", &format!("❌ 读取备份快照失败: {error}"));
            let _ = std::fs::remove_file(&path);
            return management_error(500, "导出备份失败：快照文件不可读");
        }
    };

    // 守卫随流一起被丢弃 → 文件在流生命周期结束时删除
    let guard = SnapshotGuard(path);
    let stream = tokio_util::io::ReaderStream::new(file);
    let stream = futures::StreamExt::map(stream, move |chunk| {
        let _ = &guard; // 把守卫绑进闭包，与流同生命周期
        chunk
    });

    let filename = format!("agent2api-backup-{}.db", file_stamp());
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());

    // 文件名用 HeaderValue 构造（非 ASCII 不 panic），与 download_logs 同一手法
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        response.headers_mut().insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

/// 临时快照的删除守卫（流被丢弃时删文件）。
struct SnapshotGuard(std::path::PathBuf);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// 「同一时刻只有一次恢复」的守卫（RAII：出作用域即释放）。
///
/// 用 `AtomicBool::compare_exchange` 而不是 `Mutex`：这里要的是「抢到就干活、
/// 抢不到立刻拒绝」，不是「排队等」，`try_lock` 语义用 CAS 最直白，也不必
/// 持有任何跨 await 的锁（handler 全程有 `.await`，持锁跨 await 会拖死并发）。
///
/// 进程重启后标志自然归零 —— 恢复本来就是「写完 pending 就退出」，
/// 不需要跨进程的持久化互斥。
static RESTORE_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

struct RestoreGuard;

impl RestoreGuard {
    fn acquire() -> Option<Self> {
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

/// POST /api/db/restore —— 网页端上传备份并恢复。
///
/// 流程：**流式落盘** → 校验 → 返回「即将重启」→ 触发进程自退。
///
/// ── 为什么落盘而不是进内存 ────────────────────────────────────
/// 库可达数百 MB。`Body::into_data_stream()` 逐块写文件，内存占用是常数。
///
/// ── 为什么返回之后是「进程自己退出」而不是「原地换库」──────────
/// 进程跑着的时候库是打开的，Windows 上换不了（见 `db::restore` 模块头）。
/// 所以这里只把备份**放到约定的位置**，然后让进程干净退出；下次启动时
/// `ServerState::bootstrap` 开头的 `apply_pending()` 会完成替换。
/// 容器侧靠 `restart: unless-stopped`（`docker-compose.yml`）自动拉起，
/// 用户不需要敲任何命令。
///
/// ── 自退为什么是安全的 ────────────────────────────────────────
/// 走的是与 SIGTERM 同一条收尾路径：`ServerState` 的停机广播 →
/// `server::start` 里 `serve` 返回后的 `RequestStats::flush()`，把 WAL 并回
/// 主库并清掉 `-wal` / `-shm`。不会留下未合并的 WAL 让下次启动读到旧数据。
pub async fn restore_database(State(state): State<ServerState>, request: Request) -> Response {
    // ── 并发守卫：同一时刻只允许一次恢复 ──────────────────────────
    // 没有这道闸，两个并发/重复提交会**同时**往同一个固定路径
    // `agent2api.db.restore-pending` 写：后到的 `remove_file` + `File::create`
    // 会截断前一个的写入，留下半截文件，而两个请求各自已经回话（一个说
    // 「正在重启」、一个说别的），语义全乱。抢不到的直接拒绝，让用户重试 ——
    // 比默默写坏一份 pending 强。
    let Some(_restore_guard) = RestoreGuard::acquire() else {
        logging::log("[Restore]", "⚠️  已有一项恢复正在进行，拒绝并发请求");
        return management_error(409, "已有一项恢复正在进行，请等待其完成后重试");
    };

    let pending = crate::server::config::config_dir().join(restore::PENDING_FILE);

    // ── 流式落盘 ──────────────────────────────────────────────
    // 先删旧残留：上一次没应用成功的 pending 由本次覆盖（语义正确 ——
    // 用户刚选的就是他要的那一份）。同时避免「新文件比旧的短」时留下尾巴。
    let _ = std::fs::remove_file(&pending);
    if let Err(error) = write_body_to_file(request, &pending).await {
        let _ = std::fs::remove_file(&pending);
        logging::log("[Restore]", &format!("❌ 接收备份失败: {error}"));
        return management_error(500, error);
    }

    // ── 校验 ──────────────────────────────────────────────────
    // 复用启动期那套校验（文件头 + quick_check + user_version），别写两份。
    // 这里过了不代表启动期不用再校验：两次之间文件仍可能被外部改动，
    // 而启动期那次是**替换前**的最后一道闸。
    if let Err(reason) = restore::validate_upload(&pending) {
        let _ = std::fs::remove_file(&pending);
        logging::log("[Restore]", &format!("⚠️  备份校验未通过: {reason}"));
        return management_error(400, reason);
    }

    logging::log("[Restore]", "备份已接收并通过校验，即将重启以完成恢复");

    // ── 触发自退（在响应发出去之后）────────────────────────────
    // 用 `spawn` 而不是直接调：得先把响应交还给客户端，否则连接会在
    // 「响应还没发完」时被停机流程掐断。
    //
    // 两条信号都要发，缺一不可：
    //   · `tx`（oneshot）→ 汇进 `stop_tx` → **axum 优雅停机**（端口释放、
    //     在途请求跑完）。桌面壳形态**只**靠它，随后由壳自己的
    //     `schedule_app_restart` 重启进程。
    //   · `self_exit_signal`（Notify）→ headless 的 `main` 在 `select!` 里等它，
    //     收到才**真正退出进程**、让容器的 `restart: unless-stopped` 拉起。
    //     桌面壳没人 await 它，发出去石沉大海，行为不变。
    let self_exit_signal = state.self_exit_signal();
    if let Some(tx) = state.take_self_exit() {
        crate::spawn_task(async move {
            // 留一点时间让响应写回客户端（几十毫秒足够；这里保守给 500ms）
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let _ = tx.send(());
            self_exit_signal.notify_one();
        });
    } else {
        // 拿不到停机句柄（理论上只在 bootstrap 与 start 之间才会发生）：
        // 备份已经放好了，如实告诉用户需要手动重启，别假装成功。
        logging::log("[Restore]", "⚠️  停机句柄不可用，需要手动重启以完成恢复");
        return raw_json(json!({
            "success": true,
            "data": {
                "restarting": false,
                "note": "备份已就绪，但本进程无法自行重启：请手动重启服务（docker compose restart）"
            }
        }));
    }

    raw_json(json!({
        "success": true,
        "data": {
            "restarting": true,
            "note": "正在重启以完成恢复；若 30 秒内未自动恢复，请手动执行 docker compose up -d"
        }
    }))
}

/// 把请求体逐块写进文件（常数内存）。
async fn write_body_to_file(request: Request, path: &std::path::Path) -> Result<(), String> {
    use futures::StreamExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("创建配置目录失败: {error}"))?;
    }
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|error| format!("无法写入备份文件: {error}"))?;

    let mut stream = request.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk: Bytes = chunk.map_err(|error| format!("读取上传内容失败: {error}"))?;
        file.write_all(&chunk)
            .await
            .map_err(|error| format!("写入备份文件失败: {error}"))?;
    }
    file.flush().await.map_err(|error| format!("写入备份文件失败: {error}"))?;
    Ok(())
}

/// 导出文件名的时间戳（与 `logs_api::file_stamp` 同口径：
/// 冒号在 Windows 文件名里非法，必须换成 `-`）。
fn file_stamp() -> String {
    match chrono::DateTime::from_timestamp_millis(logging::now_ms()) {
        Some(now) => now.format("%Y-%m-%dT%H-%M-%S-%3fZ").to_string(),
        None => "unknown".to_string(),
    }
}
