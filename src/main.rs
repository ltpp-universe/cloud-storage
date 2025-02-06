use bin_encrypt_decrypt::*;
use hyperlane::*;
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use tokio::fs::metadata;

const FILE_DIR: &str = "/home/cloud_storage/file";
const LOG_DIR: &str = "/home/cloud_storage/logs";
const FILE_MAX_SIZE: usize = 4_194_304;
const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_=";
const PROTOCOL_DOMAIN_NAME: &str = "https://file.ltpp.vip";
const FILE_NAME_KEY: &str = "file_name";

async fn get_file_full_path(req_file_path: &str) -> String {
    let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
    let year: String = now.format("%Y").to_string();
    let month: String = now.format("%m").to_string();
    let day: String = now.format("%d").to_string();
    let hour: String = now.format("%H").to_string();
    let minute: String = now.format("%M").to_string();
    let full_dir: String = format!(
        "{}/{}/{}/{}/{}/{}",
        FILE_DIR, year, month, day, hour, minute
    );
    let full_path: String = format!("{}{}", full_dir, req_file_path);
    let dir_path: PathBuf = PathBuf::from(&full_dir);
    let _ = tokio::fs::create_dir_all(&dir_path).await;
    full_path
}

fn replace_prefix_with_hash(input: &str) -> String {
    let (prefix, suffix) = input.rsplit_once('.').unwrap_or((input, ""));
    let mut salt: [u8; 64] = [0u8; 64];
    let _ = rand::rng().try_fill_bytes(&mut salt);
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(salt);
    let hash = hex::encode(hasher.finalize());
    format!("{}.{}", hash, suffix)
}

fn common_log(log_data: &String) -> String {
    let write_data: String = format!("{}: {}\n", current_time(), log_data);
    write_data.clone()
}

fn get_json_string(code: usize, msg: &str, data: &str) -> String {
    format!(
        "{{\"code\":{},\"msg\":\"{}\",\"data\":\"{}\"}}",
        code, msg, data
    )
}

fn resp_json(
    stream: &ArcTcpStream,
    response: &mut Response,
    log: &Log,
    content_type: &str,
    code: usize,
    msg: &str,
    data: &str,
) {
    let json_string: String = get_json_string(code, msg, data);
    log.info(
        format!(
            "{} resp_json => {}",
            stream.peer_addr().unwrap(),
            json_string
        ),
        common_log,
    );
    response
        .set_body(json_string.into())
        .set_status_code(200)
        .set_header(CONTENT_TYPE, format!("{}; {}", content_type, CHARSET_UTF_8))
        .send(&stream)
        .unwrap();
}

fn resp_bin(
    stream: &ArcTcpStream,
    response: &mut Response,
    log: &Log,
    status_code: usize,
    content_type: &str,
    data: Vec<u8>,
) {
    log.info(
        format!(
            "{} resp_bin => content_type:{} status_code:{}",
            stream.peer_addr().unwrap(),
            content_type,
            status_code
        ),
        common_log,
    );
    response
        .set_body(data)
        .set_status_code(status_code)
        .set_header(CONTENT_TYPE, format!("{}; {}", content_type, CHARSET_UTF_8))
        .send(&stream)
        .unwrap();
}

fn success_resp_json(
    stream: &ArcTcpStream,
    response: &mut Response,
    log: &Log,
    content_type: &str,
    msg: &str,
    data: &str,
) {
    println_success!("success_resp_json", " => ", msg, " ", data);
    resp_json(stream, response, log, content_type, 1, msg, data);
}

fn error_resp_json(
    stream: &ArcTcpStream,
    response: &mut Response,
    log: &Log,
    content_type: &str,
    msg: &str,
    data: &str,
) {
    println_danger!("error_resp_json", " => ", msg, " ", data);
    resp_json(stream, response, log, content_type, 0, msg, data);
}

fn success_resp_bin(
    stream: &ArcTcpStream,
    response: &mut Response,
    log: &Log,
    content_type: &str,
    data: Vec<u8>,
) {
    println_success!("success_resp_bin", " => ", content_type);
    resp_bin(stream, response, log, 200, content_type, data);
}

fn error_resp_bin(
    stream: &ArcTcpStream,
    response: &mut Response,
    log: &Log,
    content_type: &str,
    data: Vec<u8>,
) {
    println_success!("error_resp_bin", " => ", content_type);
    resp_bin(stream, response, log, 404, content_type, data);
}

fn encode_file_full_path(path: &str) -> String {
    let (prefix, suffix) = path.rsplit_once('.').unwrap_or((path, ""));
    format!("{}.{}", encrypt(CHARSET, prefix).unwrap(), suffix)
}

fn decode_file_full_path(path: &str) -> String {
    let (prefix, suffix) = path.rsplit_once('.').unwrap_or((path, ""));
    format!("{}.{}", decrypt(CHARSET, prefix).unwrap(), suffix)
}

async fn file_middleware(arc_lock_controller_data: ArcRwLockControllerData) {
    let controller_data: ControllerData = arc_lock_controller_data.write().unwrap().clone();
    let path: &String = controller_data.get_request().get_path();
    let extension_name: String = FileExtension::get_extension_name(path);
    let content_type: &str = FileExtension::parse(&extension_name).get_content_type();
    if content_type.is_empty() {
        return;
    }
    let file_path: String = decode_file_full_path(path);
    if file_path.contains("?") {
        return;
    }
    let mut response: Response = controller_data.get_response().clone();
    let stream: ArcTcpStream = controller_data.get_stream().clone().unwrap();
    let log: &Log = controller_data.get_log();
    if file_path.contains("../") {
        return error_resp_json(
            &stream,
            &mut response,
            log,
            content_type,
            &format!("{} unsafe", FILE_NAME_KEY),
            "",
        );
    }
    let body_res: Result<Vec<u8>, Box<dyn std::error::Error>> =
        async_read_from_file(&file_path).await;
    if let Ok(body) = body_res {
        return success_resp_bin(&stream, &mut response, log, content_type, body);
    }
    error_resp_bin(&stream, &mut response, log, content_type, vec![]);
}

async fn add_file(arc_lock_controller_data: ArcRwLockControllerData) {
    let controller_data: ControllerData = arc_lock_controller_data.write().unwrap().clone();
    let req: &Request = controller_data.get_request();
    let query: &RequestQuery = req.get_query();
    let mut response: Response = controller_data.get_response().clone();
    let stream: ArcTcpStream = controller_data.get_stream().clone().unwrap();
    let file_name_opt: Option<&String> = query.get(FILE_NAME_KEY);
    let log: &Log = controller_data.get_log();
    if file_name_opt.is_none() {
        return error_resp_json(
            &stream,
            &mut response,
            log,
            APPLICATION_JSON,
            &format!("missing {}", FILE_NAME_KEY),
            "",
        );
    }
    let file_name: String = replace_prefix_with_hash(&file_name_opt.unwrap());
    let file_name_path: String = format!("/{}", file_name);
    if file_name_path.contains("../") {
        return error_resp_json(
            &stream,
            &mut response,
            log,
            APPLICATION_JSON,
            &format!("{} unsafe", FILE_NAME_KEY),
            "",
        );
    }
    let extension_name: String = FileExtension::get_extension_name(&file_name_path);
    let content_type: &str = FileExtension::parse(&extension_name).get_content_type();
    if content_type.is_empty() {
        return error_resp_json(
            &stream,
            &mut response,
            log,
            APPLICATION_JSON,
            "file type not supported",
            "",
        );
    }
    let file_data: &Vec<u8> = req.get_body();
    let file_data_len: usize = file_data.len();
    if file_data_len == 0 {
        return error_resp_json(
            &stream,
            &mut response,
            log,
            APPLICATION_JSON,
            "file can not empty",
            "",
        );
    }
    if file_data_len > FILE_MAX_SIZE {
        return error_resp_json(
            &stream,
            &mut response,
            log,
            APPLICATION_JSON,
            &format!("file size over {} bytes", FILE_MAX_SIZE),
            "",
        );
    }
    let full_path: String = get_file_full_path(&file_name_path).await;
    if metadata(&full_path).await.is_ok() {
        return error_resp_json(
            &stream,
            &mut response,
            log,
            APPLICATION_JSON,
            "file already exist",
            "",
        );
    }
    let write_res: Result<(), std::io::Error> = async_write_to_file(&full_path, file_data).await;
    if let Err(err) = write_res {
        return error_resp_json(
            &stream,
            &mut response,
            log,
            APPLICATION_JSON,
            &format!("{:?}", err),
            "",
        );
    }
    let encode_full_path: String = encode_file_full_path(&full_path);
    let encode_full_url: String = format!("{}/{}", PROTOCOL_DOMAIN_NAME, encode_full_path);
    success_resp_json(
        &stream,
        &mut response,
        log,
        APPLICATION_JSON,
        "ok",
        &encode_full_url,
    );
}

async fn run_server() {
    let mut server: Server = Server::new();
    server.host("0.0.0.0");
    server.port(60006);
    server.log_dir(LOG_DIR);
    server.async_middleware(file_middleware).await;
    server.async_router("/add_file", add_file).await;
    server.listen();
}

#[tokio::main]
async fn main() {
    run_server().await;
}
