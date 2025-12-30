import subprocess
import re
from typing import List, Dict, Tuple

# 清理输出函数
def clean_output(output: str) -> str:
    if not output:
        return ""
    output = output.replace('\0', '')  # 去除空字符
    output = re.sub(r'\n+', '\n', output).strip()  # 多换行→单换行
    output = re.sub(r' +', ' ', output)  # 多空格→单空格
    return output

# 执行命令函数
def run_command(cmd: List[str]) -> Tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            shell=False
        )
        # 解码兼容
        try:
            output = result.stdout.decode("utf-8").strip()
        except UnicodeDecodeError:
            output = result.stdout.decode("latin-1").strip()
        output = clean_output(output)
        return (result.returncode == 0, output)
    except subprocess.TimeoutExpired:
        return (False, "命令执行超时（30秒）")
    except Exception as e:
        return (False, f"命令执行异常：{str(e)}")

# 规则解析函数
def parse_rules(output: str) -> List[Dict]:
    rules = []
    output = clean_output(output)
    lines = output.strip().split("\n")
    current_list = "" 

    # 字段映射：如state_filte→est，time_accept→time_range
    key_mapping = {
        "state_filte": "est",
        "time_accept": "time_range",
        "time_drop": "time_range",
        "contents": "content"  # 底层用contents，前端统一为content
    }

    # 正则定义
    param_pattern = re.compile(r'(\w+?)=(.*?)(?=\s*\w+=|$)')  # 匹配key=value（正常字段）
    content_pattern = re.compile(r'contents=(.+?)(?=\s*\w+=|$)', re.IGNORECASE | re.DOTALL)  # 匹配contents内容
    single_content_pattern = re.compile(r'\|(.*?)\|', re.DOTALL)  # 拆分|...|片段

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 识别黑白名单标题
        if "Kernel notify (BLACK)" in line:
            current_list = "black"
            continue
        elif "Kernel notify (WHITE)" in line:
            current_list = "white"
            continue

        # 匹配规则行（Rule X:）
        rule_match = re.search(r"Rule (\d+):", line)
        if not rule_match:
            continue

        # 初始化规则字典（适配Rule 1的字段结构）
        rule_id = rule_match.group(1)
        rule_dict = {
            "id": rule_id,
            "list_type": current_list,
            "action": "drop" if current_list == "black" else "accept" if current_list == "white" else "unknown",
            "src_ip": None,
            "dst_ip": None,
            "src_ip_mask": None,
            "dst_ip_mask": None,
            "src_port": None,
            "dst_port": None,
            "src_mac": None,
            "dst_mac": None,
            "proto": None,
            "est": 0,  # state_filte：0=关闭，1=开启
            "content": None,  # 最终为顿号分隔字符串
            "time_range": None,
            "interface": None
        }

        # 解析contents
        content_match = content_pattern.search(line)
        if content_match:
            content_raw = content_match.group(1).strip()
            content_fragments = single_content_pattern.findall(content_raw)
            # 过滤空片段 + 拼接为顿号分隔字符串
            content_list = [frag.strip() for frag in content_fragments if frag.strip()]
            if content_list:
                rule_dict["content"] = "、".join(content_list)  # 关键：列表转顿号字符串
            else:
                rule_dict["content"] = None

        # 解析所有key=value字段
        params = param_pattern.findall(line)
        for raw_key, raw_value in params:
            raw_key = raw_key.strip()
            raw_value = raw_value.strip()
            if not raw_value:
                continue

            # 字段映射转换
            mapped_key = key_mapping.get(raw_key, raw_key)

            # 特殊字段处理
            if mapped_key == "est":
                # state_filte值解析：true/1→1，false/0→0
                rule_dict["est"] = 1 if raw_value.lower() in ["true", "1"] else 0
            elif mapped_key == "time_range":
                # 去掉time_accept/time_drop的|分隔符
                rule_dict["time_range"] = raw_value.replace("|", "").strip()
            elif mapped_key in ["src_port", "dst_port"]:
                # 端口转换为整数（兼容异常值）
                try:
                    rule_dict[mapped_key] = int(raw_value)
                except ValueError:
                    rule_dict[mapped_key] = raw_value
            elif mapped_key == "proto":
                # 协议格式化（保留数字/协议名，转大写）
                proto_clean = re.search(r'(icmp|tcp|udp|\d+)', raw_value, re.IGNORECASE)
                rule_dict["proto"] = proto_clean.group(1).upper() if proto_clean else raw_value
            elif mapped_key in rule_dict:
                # 普通字段直接赋值（src_ip/dst_ip/mac/interface等）
                rule_dict[mapped_key] = raw_value

        rules.append(rule_dict)

    return rules