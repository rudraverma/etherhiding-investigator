"""
Human-like interaction. EtherHiding stage-1 gates increasingly require a genuine
user gesture (mousemove / scroll / click) before releasing the eth_call chain, and
score "humanness" on cursor motion and dwell. These are gentle, in-viewport actions
that never navigate away from the page under investigation.
"""

from __future__ import annotations

import asyncio
import random


async def humanize(page, profile: dict) -> None:
    vw = profile["viewport"]["width"]
    vh = profile["viewport"]["height"]

    # Curved mouse movement across the viewport.
    x, y = random.randint(40, vw - 40), random.randint(40, vh - 40)
    for _ in range(random.randint(6, 12)):
        nx = min(vw - 5, max(5, x + random.randint(-180, 180)))
        ny = min(vh - 5, max(5, y + random.randint(-120, 120)))
        steps = random.randint(5, 20)
        try:
            await page.mouse.move(nx, ny, steps=steps)
        except Exception:
            pass
        x, y = nx, ny
        await asyncio.sleep(random.uniform(0.08, 0.25))

    # Scroll down in increments, then part-way back up.
    for _ in range(random.randint(3, 6)):
        try:
            await page.mouse.wheel(0, random.randint(200, 600))
        except Exception:
            pass
        await asyncio.sleep(random.uniform(0.2, 0.6))
    try:
        await page.mouse.wheel(0, -random.randint(100, 400))
    except Exception:
        pass
    await asyncio.sleep(random.uniform(0.3, 0.8))

    # A single in-viewport click (many gates require one real click).
    try:
        await page.mouse.click(random.randint(60, vw - 60), random.randint(60, vh // 2), delay=random.randint(40, 120))
    except Exception:
        pass
    await asyncio.sleep(random.uniform(0.4, 1.0))
