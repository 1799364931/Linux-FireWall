# 定义防火墙规则和模式切换的Pydantic模型
from pydantic import BaseModel, Field
from typing import List, Optional
from typing import Literal

class FirewallRule(BaseModel):
    """防火墙规则模型，对应原有命令行的选项"""
    direction: Literal["in", "out"] = Field("in", description="规则方向（in=入站，out=出站）")
    src_ip: Optional[str] = Field(None, description="源IP地址")
    dst_ip: Optional[str] = Field(None, description="目标IP地址")
    src_ip_mask: Optional[str] = Field(None, description="源IP网段掩码")
    dst_ip_mask: Optional[str] = Field(None, description="目标IP网段掩码")
    src_port: Optional[int] = Field(None, description="源端口")
    dst_port: Optional[int] = Field(None, description="目标端口")
    src_mac: Optional[str] = Field(None, description="源MAC地址")
    dst_mac: Optional[str] = Field(None, description="目标MAC地址")
    proto: Optional[str] = Field(None, description="协议（tcp/udp/icmp）")
    time_range: Optional[str] = Field(None, description="时间段（格式：12:00 14:00）")
    content: Optional[List[str]] = Field(None, description="内容关键字列表")
    interface: Optional[str] = Field(None, description="网络接口")
    est: Optional[int] = Field(None, description="是否只允许已建立连接的包（1/0）")
    action: str = Field(..., description="动作（drop/accept）")

class ModeChange(BaseModel):
    """模式切换模型（对应防火墙的黑白名单）"""
    mode: Literal["drop", "accept"]  # 只允许传入drop/accept
