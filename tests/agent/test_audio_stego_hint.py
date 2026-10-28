"""Audio-stego prompt hint (audit follow-up, 2026-10-27).

Measured: three DASBOOK audio challenges (MP3隐写 / 波形图04 / 频谱图) all hit
the 11-minute cap while the audio reference existed but was never loaded --
the ``hear_with_your_eyes`` goal selected NO skill at all, so only a
deterministic prompt block can reach the model. These tests pin that block:
it appears only for audio-shaped goals, and it names the four things the
failed runs got wrong (ffmpeg path, vertically mirrored spectrogram text,
MP3Stego absence, the 3-submission platform cap).
"""

from __future__ import annotations

from vulnclaw.agent.solver import _audio_stego_instruction


def test_audio_goal_gets_the_first_moves_block():
    text = _audio_stego_instruction(
        "Solve CTF2 challenge '[7.3.2 MP3音频]MP3隐写' (category 第07章 MP3音频)"
    )
    assert "Audio steganography: first moves" in text
    assert ".ir-tools/bin/ffmpeg.exe" in text
    assert "showspectrumpic" in text


def test_spectrum_only_goal_still_gets_it():
    """hear_with_your_eyes matched no skill at all; the goal says only 频谱图."""
    text = _audio_stego_instruction(
        "Solve CTF2 challenge '[7.3.4 频谱图]hear_with_your_eyes' (difficulty Easy)"
    )
    assert "Audio steganography: first moves" in text
    assert "ImageOps.flip" in text


def test_mp3_hint_points_at_the_installed_tool_and_the_submit_cap():
    text = _audio_stego_instruction("[7.3.2 MP3音频]MP3隐写 音频")
    lowered = text.lower()
    assert "decode.exe -x -p" in lowered
    assert "standard mp3stego" in lowered
    assert "3 automatic attempts" in lowered


def test_non_audio_goal_is_byte_identical():
    assert _audio_stego_instruction("Solve a web SQL injection challenge on shop.test") == ""
    assert _audio_stego_instruction("") == ""
