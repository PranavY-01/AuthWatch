import io

from rich.console import Console

from authwatch import render
from authwatch.render import err_console, safe_display


def rendered(text: str) -> str:
    buf = io.StringIO()
    Console(file=buf, highlight=False, emoji=False, force_terminal=True, width=200).print(
        f"[bold]{safe_display(text)}[/bold]", soft_wrap=True)
    return buf.getvalue()


def test_untrusted_strings_render_literally():
    """Case 59: usernames containing ESC, [red] markup, :smile: and an RTL override render
    literally and no ESC byte from the value reaches the output."""
    for value, visible in [("[red]root[/red]", "[red]root[/red]"), (":smile:", ":smile:"),
                           ("admin\x1b[2J", "admin\\x1b[2J"), ("abc‮def", "abc\\u202edef")]:
        out = rendered(value)
        plain = out.replace("\x1b[1m", "").replace("\x1b[0m", "")
        assert visible in plain
        assert "\x1b[2J" not in out and "‮" not in out and "😄" not in out


def test_trailing_backslash_cannot_escape_markup():
    out = rendered("evil\\")
    assert "evil\\" in out and "[/bold]" not in out


def test_truncation():
    s = safe_display("x" * 500)
    assert len(s) == 201 and s.endswith("…")


def test_consoles_configured_without_emoji_or_highlighting():
    for console in (render.console, err_console):
        assert console._emoji is False and console._highlight is False
    assert err_console.stderr is True
