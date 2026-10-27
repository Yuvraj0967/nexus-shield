import asyncio, os, tempfile
from nexus_shield import honeypot, telemetry, sdr, analysis, vaccine
from nexus_shield.cli import simulate

def test_pipeline():
    evs, ben = simulate()
    assert len(sdr.correlate(evs, sdr.synth(evs))) == len(evs)
    assert all(analysis.signature(e)["automated"] for e in evs)
    v = vaccine.make(evs)
    r = vaccine.evaluate(v, evs, ben)
    assert r["recall"] == 1 and r["safe_to_deploy"]

def test_honeypot_logs():
    log = tempfile.mktemp()
    async def go():
        srv = await asyncio.start_server(lambda r, w: honeypot._handle(r, w, "t", log), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        await r.read(5); w.write(b"root\nwget x\n"); await w.drain(); w.close()
        await asyncio.sleep(0.3); srv.close()
    asyncio.run(go())
    assert telemetry.load(log)[0].payloads[:2] == ["root", "wget x"]
