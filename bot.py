"""Discord front-end. Run on the host (or as the 'bot' compose service)."""
import json
import os
import socket
import struct
import uuid

import discord
from discord import app_commands

from config import ALLOWED_HOSTNAMES, ALLOWED_PREFIXES, DISCORD_TOKEN
from evidence import Evidence
import jobs

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


def allowed(target):
    return target.startswith(ALLOWED_PREFIXES) or any(
        target.endswith(h) for h in ALLOWED_HOSTNAMES
    )


THEME = {"cyan": 0x00E5FF, "green": 0x00FF88, "amber": 0xFFB020, "red": 0xFF3B5C}


def sec_embed(title, description="", color="cyan"):
    e = discord.Embed(title=f"J2SEC // {title.upper()}", description=description, color=THEME[color])
    e.set_footer(text="J2SEC SECURITY OPERATIONS // HTB TOOLKIT")
    return e


def field(e, label, value, inline=True):
    e.add_field(name=f"// {label.upper()}", value=value, inline=inline)
    return e


def status_label(value):
    return str(value or "unknown").replace("_", " ").upper()


def err(msg, title="ACCESS / CONTROL ERROR"):
    return sec_embed(title, f"```ansi\n[!] {msg}\n```", "red")


def decoded_flags(job):
    try:
        value = json.loads(job.get("flags") or "[]")
        return value if isinstance(value, list) else []
    except (TypeError, json.JSONDecodeError):
        return []


def interface_ipv4(name):
    """Return an interface IPv4 address from the host network namespace."""
    try:
        import fcntl
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            request = struct.pack("256s", name[:15].encode())
            result = fcntl.ioctl(sock.fileno(), 0x8915, request)  # SIOCGIFADDR
        return socket.inet_ntoa(result[20:24])
    except (ImportError, OSError):
        return None


def htb_vpn_interface():
    """Find the active host tunnel used for the HTB VPN."""
    preferred = ("tun0", "tun1", "tap0", "wg0")
    names = [name for _, name in socket.if_nameindex()]
    ordered = list(preferred) + [
        name for name in names
        if name.startswith(("tun", "tap", "wg")) and name not in preferred
    ]
    for name in ordered:
        if name not in names:
            continue
        ip = interface_ipv4(name)
        if ip:
            return name, ip
    return None, None


VPN_CONTROL_SOCKET = os.getenv("VPN_CONTROL_SOCKET", "/run/htblab/vpn.sock")


def vpn_control(action):
    """Ask the host helper to perform one fixed OpenVPN service action."""
    request = (json.dumps({"action": action}) + "\n").encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(12)
            sock.connect(VPN_CONTROL_SOCKET)
            sock.sendall(request)
            response = b""
            while b"\n" not in response and len(response) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return json.loads(response.decode().strip())
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "state": "unavailable", "message": str(exc)}


def vpn_embed(action, result):
    interface, vpn_ip = htb_vpn_interface()
    state = result.get("state", "unknown")
    connected = bool(vpn_ip) and state == "active"
    color = 0x57F287 if connected else (0xFEE75C if state in {"activating", "deactivating"} else 0xED4245)
    icon = "🟢" if connected else ("🟡" if color == 0xFEE75C else "🔴")

    e = discord.Embed(
        title="J2SEC // HTB VPN // TUNNEL CONTROL",
        description=f"{icon} **{state.replace('_', ' ').title()}**",
        color=color,
    )
    e.add_field(name="Service", value=f"`{state}`", inline=True)
    e.add_field(name="Interface", value=f"`{interface or '—'}`", inline=True)
    e.add_field(name="VPN IP", value=f"`{vpn_ip or '—'}`", inline=True)
    if action != "status":
        e.add_field(name="Action", value=f"`{action}`", inline=True)
    message = result.get("message")
    if message and not result.get("ok"):
        e.add_field(name="Details", value=message[:1000], inline=False)
    e.set_footer(text="J2Sec's HTB Toolkit • Host-managed OpenVPN")
    return e


@tree.command(name="vpn", description="Manage the HTB VPN connection")
@app_commands.describe(action="VPN action to perform")
@app_commands.choices(action=[
    app_commands.Choice(name="Status", value="status"),
    app_commands.Choice(name="Start", value="start"),
    app_commands.Choice(name="Stop", value="stop"),
    app_commands.Choice(name="Restart", value="restart"),
])
async def vpn(
    interaction: discord.Interaction,
    action: app_commands.Choice[str] = None,
):
    selected = action.value if action else "status"

    if selected != "status":
        permissions = getattr(interaction.user, "guild_permissions", None)
        if not permissions or not permissions.administrator:
            await interaction.response.send_message(
                embed=err("ADMINISTRATOR CLEARANCE REQUIRED FOR VPN STATE CHANGES."),
                ephemeral=True,
            )
            return
        await interaction.response.defer()

    result = vpn_control(selected)
    embed = vpn_embed(selected, result)
    if selected == "status":
        await interaction.response.send_message(embed=embed)
    else:
        await interaction.followup.send(embed=embed)


@tree.command(name="htb", description="Queue an authorized HTB lab run")
@app_commands.describe(
    ip="Target IP (must be in the HTB allowlist)",
    platform="Target platform",
    notes="Optional starting info, e.g. credentials as user:pass",
)
@app_commands.choices(
    platform=[
        app_commands.Choice(name="Linux", value="linux"),
        app_commands.Choice(name="Windows", value="windows"),
        app_commands.Choice(name="Other", value="other"),
    ]
)
async def htb(
    interaction: discord.Interaction,
    ip: str,
    platform: app_commands.Choice[str],
    notes: str = "",
):
    if not allowed(ip):
        await interaction.response.send_message(
            embed=err(f"TARGET {ip} FAILED HTB RANGE VALIDATION.", "TARGET REJECTED")
        )
        return
    job_id = uuid.uuid4().hex[:8]
    jobs.create(job_id, ip, platform.value, notes)
    e = sec_embed("TARGET ACQUISITION", "**◈ TARGET VALIDATED**\n`HTB RANGE VERIFIED // OPERATION QUEUED`", "cyan")
    field(e, "Operation ID", f"`{job_id.upper()}`")
    field(e, "Target", f"`{ip}`")
    field(e, "Platform", f"`{platform.value.upper()}`")
    field(e, "Runner State", "`AWAITING EXECUTION`", False)
    if notes:
        field(e, "Operator Input", "`SUPPLIED // REDACTED`", False)
    await interaction.response.send_message(embed=e)


@tree.command(name="status", description="Check a job's status")
async def status(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j:
        await interaction.response.send_message(embed=err("OPERATION ID NOT FOUND.", "OPERATION LOOKUP"))
        return
    e = discord.Embed(title=f"Job `{j['id']}`", color=0x57F287)
    e.add_field(name="Target", value=f"`{j['ip']}` ({j['platform']})")
    e.add_field(name="Status", value=j["status"])
    flags = ", ".join(decoded_flags(j)) or "none"
    field(e, "Artifacts", f"`{flags}`", False)
    await interaction.response.send_message(embed=e)


@tree.command(name="cancel", description="Cancel a running/queued job")
async def cancel(interaction: discord.Interaction, job_id: str):
    if not jobs.get(job_id):
        await interaction.response.send_message(embed=err("OPERATION ID NOT FOUND.", "OPERATION LOOKUP"))
        return
    jobs.update(job_id, status="cancelled")
    e = sec_embed("OPERATION TERMINATED", "**■ EXECUTION HALTED BY OPERATOR**", "red")
    field(e, "Operation ID", f"`{job_id.upper()}`")
    field(e, "State", "`CANCELLED`")
    await interaction.response.send_message(embed=e)


@tree.command(name="approve", description="Approve a pending exploit-tier action")
async def approve(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j or j["status"] != "awaiting_approval":
        await interaction.response.send_message(
            embed=err("OPERATION IS NOT AWAITING AUTHORIZATION.", "AUTHORIZATION CONTROL")
        )
        return
    jobs.update(job_id, status="approved")
    e = sec_embed("AUTHORIZATION GRANTED", "**◈ PRIVILEGED ACTION CLEARED**", "green")
    field(e, "Operation ID", f"`{job_id.upper()}`")
    field(e, "Decision", "`APPROVED`")
    await interaction.response.send_message(embed=e)


@tree.command(name="deny", description="Deny a pending exploit-tier action")
async def deny(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j or j["status"] != "awaiting_approval":
        await interaction.response.send_message(
            embed=err("OPERATION IS NOT AWAITING AUTHORIZATION.", "AUTHORIZATION CONTROL")
        )
        return
    jobs.update(job_id, status="denied")
    e = sec_embed("AUTHORIZATION DENIED", "**■ PRIVILEGED ACTION BLOCKED**", "red")
    field(e, "Operation ID", f"`{job_id.upper()}`")
    field(e, "Decision", "`DENIED`")
    await interaction.response.send_message(embed=e)


@tree.command(name="results", description="Show flags and recent evidence")
async def results(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j:
        await interaction.response.send_message(embed=err("OPERATION ID NOT FOUND.", "OPERATION LOOKUP"))
        return
    flags = ", ".join(decoded_flags(j)) or "none retrieved"
    evidence_tail = Evidence(job_id).tail(15)
    if len(evidence_tail) > 3500:
        evidence_tail = evidence_tail[-3500:]
    e = sec_embed("OPERATION REPORT", f"`OPS::{job_id.upper()} // {status_label(j[\'status\'])}`", "green")
    field(e, "Target", f"`{j[\'ip\']}`")
    field(e, "Platform", f"`{j[\'platform\'].upper()}`")
    field(e, "Recovered Artifacts", f"`{flags}`", False)
    e.add_field(
        name="// EVIDENCE STREAM",
        value=f"```\n{evidence_tail}\n```",
        inline=False,
    )
    await interaction.response.send_message(embed=e)


@tree.command(name="jobs", description="List recent jobs")
async def list_jobs(interaction: discord.Interaction):
    lines = [f"`{j['id']}`  {j['ip']:<16} {j['status']}" for j in jobs.recent()]
    await interaction.response.send_message(
        embed=discord.Embed(
            title="Recent jobs",
            description="\n".join(lines) or "none",
            color=0x5865F2,
        )
    )


@client.event
async def on_ready():
    jobs.init()
    await client.change_presence(
        activity=discord.Game(name="J2Sec's HTB Toolkit")
    )
    await tree.sync()
    print(f"Logged in as {client.user} — commands synced")


if __name__ == "__main__":
    if not DISCORD_TOKEN or DISCORD_TOKEN == "PUT-YOUR-BOT-TOKEN-HERE":
        raise RuntimeError("DISCORD_TOKEN is not configured")
    client.run(DISCORD_TOKEN)
