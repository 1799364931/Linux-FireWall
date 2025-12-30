import os
import asyncio
import logging
import signal
import subprocess
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import List, Dict, Tuple, Optional
from fastapi.middleware.cors import CORSMiddleware
import re 

from models.firewall_models import FirewallRule, ModeChange
from core.connection_manager import manager
from utils.command_utils import run_command, parse_rules

# 加载环境变量
load_dotenv()
# 读取.env配置，默认值设为空字符串
FIREWALL_CONTROLLER_CMD = os.getenv("FIREWALL_CONTROLLER_CMD", "") 
FIREWALL_LOGGER_CMD = os.getenv("FIREWALL_LOGGER_CMD", "")  
KERNEL_MODULE = os.getenv("KERNEL_MODULE", "")  

# 添加配置校验
if not FIREWALL_CONTROLLER_CMD or not os.path.exists(FIREWALL_CONTROLLER_CMD):
    raise RuntimeError(f"错误：请在.env文件中配置正确的FIREWALL_CONTROLLER_CMD绝对路径，当前值：{FIREWALL_CONTROLLER_CMD}")
if not FIREWALL_LOGGER_CMD or not os.path.exists(FIREWALL_LOGGER_CMD):
    raise RuntimeError(f"错误：请在.env文件中配置正确的FIREWALL_LOGGER_CMD绝对路径，当前值：{FIREWALL_LOGGER_CMD}")
if not KERNEL_MODULE or not os.path.exists(KERNEL_MODULE):
    raise RuntimeError(f"错误：请在.env文件中配置正确的KERNEL_MODULE绝对路径，当前值：{KERNEL_MODULE}")

# 安全认证
security = HTTPBasic()
USERNAME = os.getenv("API_USER", "admin")
PASSWORD = os.getenv("API_PASS", "admin123456")

app = FastAPI(title="Linux防火墙管理API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # 前端运行的地址（端口3000）
    allow_credentials=True,  # 允许携带认证信息（Basic认证需要这个）
    allow_methods=["*"],     # 允许所有HTTP方法（包括OPTIONS预检请求）
    allow_headers=["*"],     # 允许所有请求头
)

# 日志配置
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# 日志相关全局变量
logger_process = None  # 日志器进程
logger_pid = None      # 日志器PID
logger_logs = []       # 存储格式：[{"id": 日志唯一ID, "content": 日志内容}]
LOG_MAX_LENGTH = 200   # 日志最大条数
log_id = 0             # 新增：日志ID计数器（自增）
logger_time = ""  # 暂存防火墙logger输出的时间行（如15:47:19）

# API认证
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != USERNAME or credentials.password != PASSWORD:
        raise HTTPException(
            status_code=401,
            detail="认证失败，请检查用户名密码",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials

# API接口
@app.post("/api/rules", dependencies=[Depends(authenticate)])
async def add_rule(rule: FirewallRule):
    """添加防火墙规则"""
    # 构建命令行参数
    cmd = [FIREWALL_CONTROLLER_CMD, "--add"]
    # 拼接规则参数
    if rule.direction == "out":
        cmd.append("--out")
    if rule.src_ip:
        cmd.extend(["--src-ip", rule.src_ip])
    if rule.dst_ip:
        cmd.extend(["--dst-ip", rule.dst_ip])
    if rule.src_ip_mask:
        cmd.extend(["--src-ip-mask", rule.src_ip_mask])
    if rule.dst_ip_mask:
        cmd.extend(["--dst-ip-mask", rule.dst_ip_mask])
    if rule.src_port:
        cmd.extend(["--src-port", str(rule.src_port)])
    if rule.dst_port:
        cmd.extend(["--dst-port", str(rule.dst_port)])
    if rule.src_mac:
        cmd.extend(["--src-mac", rule.src_mac])
    if rule.dst_mac:
        cmd.extend(["--dst-mac", rule.dst_mac])
    if rule.proto:
        cmd.extend(["--proto", rule.proto])
    if rule.time_range:
        # 区分time-drop和time-accept
        time_flag = "--time-drop" if rule.action == "drop" else "--time-accept"
        cmd.extend([time_flag, rule.time_range])
    if rule.content:
        # 拼接内容关键字
        cmd.extend(["--content"] + rule.content)
    if rule.interface:
        cmd.extend(["--interface", rule.interface])
    if rule.est is not None:
        cmd.extend(["--est", str(rule.est)])
    # 添加动作（drop/accept）
    cmd.extend(["--" + rule.action])

    # 执行同步命令
    success, output = run_command(cmd)
    if not success:
        raise HTTPException(status_code=500, detail=f"添加规则失败：{output}")
    return {"code": 200, "message": "规则添加成功", "data": output}

@app.delete("/api/rules/{rule_id}", dependencies=[Depends(authenticate)])
async def delete_rule(rule_id: str):
    """删除防火墙规则"""
    cmd = [FIREWALL_CONTROLLER_CMD, "--del", rule_id]
    success, output = run_command(cmd)
    if not success:
        raise HTTPException(status_code=500, detail=f"删除规则失败：{output}")
    return {"code": 200, "message": "规则删除成功", "data": output}

@app.get("/api/rules", dependencies=[Depends(authenticate)])
async def list_rules():
    """获取所有防火墙规则"""
    cmd = [FIREWALL_CONTROLLER_CMD, "--list"]
    success, output = run_command(cmd)
    logger.info(f"防火墙--list原始输出：{output}")
    print(f"防火墙--list原始输出：{output}") 
    print(f"FIREWALL_CONTROLLER_CMD执行结果：success={success}, output={output}")
    if not success:
        raise HTTPException(status_code=500, detail=f"获取规则失败：{output}")
    # 解析输出为规则列表
    rules = parse_rules(output)
    return {"code": 200, "message": "获取规则成功", "data": rules}

@app.post("/api/mode", dependencies=[Depends(authenticate)])
async def change_mode(mode: ModeChange):
    """切换黑白名单模式（修复参数映射问题）"""
    # 限制mode为drop/accept
    if mode.mode not in ["drop", "accept"]:
        raise HTTPException(status_code=400, detail="模式只能是drop（默认拒绝）或accept（默认允许）")
    # 定义逻辑模式→防火墙实际参数的映射
    mode_mapping = {
        "drop": "b",    # drop（默认拒绝）→ 防火墙--mode b（黑名单）
        "accept": "w"   # accept（默认允许）→ 防火墙--mode w（白名单）
    }
    firewall_mode = mode_mapping[mode.mode]
    cmd = [FIREWALL_CONTROLLER_CMD, "--mode", firewall_mode]
    success, output = run_command(cmd)
    if not success:
        raise HTTPException(status_code=500, detail=f"切换模式失败：{output}")
    mode_desc = "黑名单（默认拒绝所有流量）" if mode.mode == "drop" else "白名单（默认允许所有流量）"
    return {
        "code": 200,
        "message": f"已切换为{mode.mode}模式（{mode_desc}）",
        "data": output
    }

@app.post("/api/system/start", dependencies=[Depends(authenticate)])
async def start_firewall():
    """启动防火墙（加载内核模块）"""
    # 先检查模块是否已加载
    kernel_module_name = KERNEL_MODULE.split("/")[-1].replace(".ko", "")
    result = subprocess.run(
        ["lsmod"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if kernel_module_name in result.stdout:
        # 模块已加载，直接返回成功，不执行insmod
        return {"code": 200, "message": "防火墙已处于启动状态，无需重复启动", "data": ""}
    # 原有的启动逻辑
    cmd = ["sudo", "insmod", KERNEL_MODULE]
    success, output = run_command(cmd)
    if not success:
        raise HTTPException(status_code=500, detail=f"启动防火墙失败：{output}")
    return {"code": 200, "message": "防火墙启动成功", "data": output}

@app.post("/api/system/stop", dependencies=[Depends(authenticate)])
async def stop_firewall():
    """停止防火墙（卸载内核模块）"""
    kernel_module_name = KERNEL_MODULE.split("/")[-1].replace(".ko", "")
    cmd = ["sudo", "rmmod", kernel_module_name]
    success, output = run_command(cmd)
    if not success:
        raise HTTPException(status_code=500, detail=f"停止防火墙失败：{output}")
    return {"code": 200, "message": "防火墙停止成功", "data": output}

# 获取防火墙状态接口
@app.get("/api/system/status", dependencies=[Depends(authenticate)])
async def get_firewall_status():
    """获取防火墙当前状态（内核模块是否加载）"""
    # 提取内核模块名（比如KERNEL_MODULE是/path/firewall.ko，提取firewall）
    kernel_module_name = KERNEL_MODULE.split("/")[-1].replace(".ko", "")
    # 执行lsmod命令，检查模块是否已加载
    cmd = ["lsmod", "|", "grep", kernel_module_name]
    result = subprocess.run(
        ["lsmod"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # 判断模块是否在输出中
    is_running = kernel_module_name in result.stdout
    status = "running" if is_running else "stopped"
    return {
        "code": 200,
        "message": "获取状态成功",
        "data": {
            "is_running": is_running,  # 是否启动
            "status": status  # running/stopped
        }
    }


# 日志器（logger）管理接口
@app.post("/api/logger/start", dependencies=[Depends(authenticate)])
async def start_logger():
    global logger_process, logger_pid, logger_logs
    if logger_process and logger_process.returncode is None:
        return {"code": 200, "message": "日志器已在运行", "data": {}}
    
    try:
        # 添加bufsize=0禁用缓冲区，实时读取日志
        logger_process = await asyncio.create_subprocess_exec(
            FIREWALL_LOGGER_CMD,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.PIPE,
            preexec_fn=os.setsid,
            bufsize=0  # 禁用缓冲区，日志逐行实时输出
        )
        logger_pid = logger_process.pid
        
        async def read_logs():
            global logger_logs, log_id
            buffer = ""  # 字符缓冲，拼接单行内容
            while logger_process and logger_process.returncode is None:
                chunk = await logger_process.stdout.read(1)  # 逐字符读取
                if not chunk:
                    break
                char = chunk.decode("utf-8", errors="ignore")
                
                if char == "\n":  # 遇到换行，处理当前行
                    # 清理行首尾的空白字符（空格/制表符/换行）
                    log_content_raw = buffer.strip()
                    buffer = ""  # 重置缓冲
                    
                    # 过滤纯空行（底层输出的空行）
                    if not log_content_raw:
                        continue
                    
                    # 验证是否是有效日志行（以时间开头：HH:MM:SS.ssssss）
                    # 正则适配：带毫秒的时间格式（如15:47:19.578381）
                    valid_log_pattern = re.match(r"^\d{2}:\d{2}:\d{2}\.\d{6}.*", log_content_raw)
                    if valid_log_pattern:
                        # 有效日志：添加后端时间戳（可选，也可以去掉，只保留底层原日志）
                        backend_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                        final_log = f"[{backend_time}] {log_content_raw}"
                        
                        # 写入日志列表，控制最大长度
                        logger_logs.append({"id": log_id, "content": final_log})
                        log_id += 1
                        if len(logger_logs) > LOG_MAX_LENGTH:
                            del logger_logs[0]
                        
                        print(f"✅ 后端读取到有效日志：{final_log}")
                    else:
                        print(f"⚠️  过滤非有效日志行：{log_content_raw}")
                else:
                    buffer += char 
        
        asyncio.create_task(read_logs())
        return {"code": 200, "message": "日志器启动成功", "data": {}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动失败：{str(e)}")


@app.post("/api/logger/stop", dependencies=[Depends(authenticate)])
async def stop_logger():
    global logger_process, logger_pid
    if not logger_process or logger_process.returncode is not None:
        return {"code": 200, "message": "日志器未运行", "data": {}}
    
    try:
        # 强制终止进程（解决sudo进程杀不掉问题）
        logger_process.terminate()
        try:
            await asyncio.wait_for(logger_process.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            if logger_pid:
                os.killpg(os.getpgid(logger_pid), signal.SIGKILL)
        
        # 重置全局变量
        logger_process = None
        logger_pid = None
        return {"code": 200, "message": "日志器已停止", "data": {}}
    except Exception as e:
        logger_process = None
        logger_pid = None
        raise HTTPException(status_code=500, detail=f"停止失败：{str(e)}")

@app.get("/api/logger/logs", dependencies=[Depends(authenticate)])
async def get_logs():
    global logger_logs
    return {"code": 200, "data": {"logs": logger_logs}}

# 增量获取日志接口
@app.get("/api/logger/logs/increment", dependencies=[Depends(authenticate)])
async def get_increment_logs(last_id: int = 0):
    """按ID增量返回日志：只返回ID大于last_id的内容"""
    global logger_logs
    increment_logs = [log for log in logger_logs if log["id"] > last_id]
    # 获取当前最大日志ID
    current_max_id = logger_logs[-1]["id"] if logger_logs else 0
    return {
        "code": 200,
        "data": {
            "new_logs": increment_logs,
            "current_max_id": current_max_id
        }
    }

@app.post("/api/logger/clear", dependencies=[Depends(authenticate)])
async def clear_logs():
    global logger_logs, log_id
    logger_logs = []
    log_id = 0  # 重置ID计数器
    return {"code": 200, "message": "日志已清空", "data": {}}

@app.get("/api/logger/status", dependencies=[Depends(authenticate)])
async def get_logger_status():
    global logger_process
    is_running = False
    if logger_process and logger_process.returncode is None:
        is_running = True
    return {"code": 200, "data": {"is_running": is_running}}

# 启动服务（需以root权限运行）
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,  
        host="0.0.0.0",
        port=8001,
        reload=False 
    )