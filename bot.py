"""Discord front-end. Run on the host (or as the 'bot' compose service)."""
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
        target.endswith(h) for h in ALLOWED_HOSTNAMES)


def err(msg):
    e = discord.Embed(description=msg, color=0xED4245)
    return e


@tree.command(name="htb", description="Queue an authorized HTB lab run")
@app_commands.describe(
    ip="Target IP (must be in the HTB allowlist)",
    platform="Target platform",
    notes="Optional starting info, e.g. credentials as user:pass")
async def htb(interaction: discord.Interaction, ip: str,
              platform: app_commands.Choice[str],
              notes: str = ""):
    if not allowed(ip):
        await interaction.response.send_message(
            embed=err(f"❌ `{ip}` is not in the HTB allowlist. Refusing."))
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
    flags = ", ".join(j["flags"]) or "none"
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
            embed=err("That job is not waiting for approval."))
        return
    jobs.update(job_id, status="approved")
    await interaction.response.send_message(f"✅ Job `{job_id}` action approved.")


@tree.command(name="deny", description="Deny a pending exploit-tier action")
async def deny(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j or j["status"] != "awaiting_approval":
        await interaction.response.send_message(
            embed=err("That job is not waiting for approval."))
        return
    jobs.update(job_id, status="denied")
    await interaction.response.send_message(f"🚫 Job `{job_id}` action denied.")


@tree.command(name="results", description="Show flags and recent evidence")
async def results(interaction: discord.Interaction, job_id: str):
    j = jobs.get(job_id)
    if not j:
        await interaction.response.send_message(embed=err("Job not found."))
        return
    flags = ", ".join(j["flags"]) or "none retrieved"
    e = discord.Embed(title=f"Results for `{job_id}`", color=0x57F287)
    e.add_field(name="Status", value=j["status"], inline=False)
    e.add_field(name="Flags", value=f"`{flags}`", inline=False)
    e.add_field(name="Evidence tail", value=f"```\n{Evidence(job_id).tail(15)}\n```",
                inline=False)
    await interaction.response.send_message(embed=e)


@tree.command(name="jobs", description="List recent jobs")
async def list_jobs(interaction: discord.Interaction):
    lines = [f"`{j['id']}`  {j['ip']:<16} {j['status']}" for j in jobs.recent()]
    await interaction.response.send_message(
        embed=discord.Embed(title="Recent jobs",
                            description="\n".join(lines) or "none", color=0x5865F2))


@client.event
async def on_ready():
    jobs.init()
    await tree.sync()
    print(f"Logged in as {client.user} — commands synced")


if __name__ == "__main__":
    client.run(DISCORD_TOKEN)
