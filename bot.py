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


def err(msg):
    return discord.Embed(description=msg, color=0xED4245)


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
        title="J2Sec • HTB VPN",
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
                embed=err("🔒 Administrator permission is required to change the HTB VPN."),
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
            embed=err(f"❌ `{ip}` is not in the HTB allowlist. Refusing.")
        )
        return
    job_id = uuid.uuid4().hex[:8]
    jobs.create(job_id, ip, platform.value, notes)
    e = discord.Embed(title="🚀 Job queued", color=0x5865F2)
    e.add_field(name="Job ID", value=f"`{job_id}`")
    e.add_field(name="Target", value=f"`{ip}` ({platform.value})")
    if notes:
        e.add_field(name="Notes", value="*(credentials supplied)*")
    await interaction.response.send_message(embed=e)


@tree.command(name="status", description="Check a job's status")
async def status(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j:
        await interaction.response.send_message(embed=err("Job not found."))
        return
    e = discord.Embed(title=f"Job `{j['id']}`", color=0x57F287)
    e.add_field(name="Target", value=f"`{j['ip']}` ({j['platform']})")
    e.add_field(name="Status", value=j["status"])
    flags = ", ".join(decoded_flags(j)) or "none"
    e.add_field(name="Flags", value=f"`{flags}`")
    await interaction.response.send_message(embed=e)


@tree.command(name="cancel", description="Cancel a running/queued job")
async def cancel(interaction: discord.Interaction, job_id: str):
    if not jobs.get(job_id):
        await interaction.response.send_message(embed=err("Job not found."))
        return
    jobs.update(job_id, status="cancelled")
    await interaction.response.send_message(f"🛑 Job `{job_id}` cancelled.")


@tree.command(name="approve", description="Approve a pending exploit-tier action")
async def approve(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j or j["status"] != "awaiting_approval":
        await interaction.response.send_message(
            embed=err("That job is not waiting for approval.")
        )
        return
    jobs.update(job_id, status="approved")
    await interaction.response.send_message(f"✅ Job `{job_id}` action approved.")


@tree.command(name="deny", description="Deny a pending exploit-tier action")
async def deny(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j or j["status"] != "awaiting_approval":
        await interaction.response.send_message(
            embed=err("That job is not waiting for approval.")
        )
        return
    jobs.update(job_id, status="denied")
    await interaction.response.send_message(f"🚫 Job `{job_id}` action denied.")


@tree.command(name="results", description="Show flags and recent evidence")
async def results(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j:
        await interaction.response.send_message(embed=err("Job not found."))
        return
    flags = ", ".join(decoded_flags(j)) or "none retrieved"
    evidence_tail = Evidence(job_id).tail(15)
    if len(evidence_tail) > 3500:
        evidence_tail = evidence_tail[-3500:]
    e = discord.Embed(title=f"Results for `{job_id}`", color=0x57F287)
    e.add_field(name="Status", value=j["status"], inline=False)
    e.add_field(name="Flags", value=f"`{flags}`", inline=False)
    e.add_field(
        name="Evidence tail",
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
