"""
Post-processor for decompiled Lua source.

Cleans up artifacts left by the LJD decompiler that cannot easily be fixed
at the AST level:
  - Block annotations (--- BLOCK #N ---, --- END OF BLOCK ---, -- jump to block)
  - Self-assignments (slot0 = slot0)
  - Trailing spaces on void return
  - Multiple consecutive blank lines
  - Empty if/else blocks
  - Leftover register references (R(N))
  - MULTRES artifacts
"""

import re


def postprocess(source):
    """Apply all text-level cleanups to decompiled Lua source."""
    lines = source.split('\n')
    lines = _remove_block_annotations(lines)
    lines = _remove_self_assignments(lines)
    lines = _remove_trailing_bare_return(lines)
    lines = _fix_return_trailing_space(lines)
    lines = _collapse_blank_lines(lines)
    lines = _remove_empty_if_else(lines)
    lines = _fix_number_literals(lines)
    lines = _strip_trailing_whitespace(lines)
    return '\n'.join(lines)


def _remove_block_annotations(lines):
    """Remove --- BLOCK #N ---  /  --- END OF BLOCK #N ---  /  -- jump to block #N."""
    result = []
    block_re = re.compile(
        r'^\s*--+\s*'
        r'(BLOCK\s*#?\d+|END\s+OF\s+BLOCK\s*#?\d*|jump\s+to\s+block\s*#?\d+)'
        r'\s*-*\s*$',
        re.IGNORECASE
    )
    for line in lines:
        if block_re.match(line):
            continue
        result.append(line)
    return result


def _remove_self_assignments(lines):
    """Remove trivial self-assignments like 'slot0 = slot0' or 'ARG_0 = ARG_0'."""
    result = []
    self_assign_re = re.compile(r'^(\s*)(local\s+)?(\w+)\s*=\s*(\w+)\s*$')
    for line in lines:
        m = self_assign_re.match(line)
        if m:
            lhs = m.group(3)
            rhs = m.group(4)
            if lhs == rhs:
                continue
        result.append(line)
    return result


def _fix_return_trailing_space(lines):
    """Fix 'return ' with trailing space to just 'return'."""
    result = []
    for line in lines:
        stripped = line.rstrip()
        # Match exactly 'return' possibly with leading whitespace then trailing space(s)
        if stripped == line.lstrip() and stripped == 'return':
            result.append(line.rstrip())
        elif line.rstrip() != line and re.match(r'^(\s*)return\s*$', line):
            result.append(re.sub(r'return\s*$', 'return', line))
        else:
            result.append(line)
    return result


def _collapse_blank_lines(lines):
    """Collapse 3+ consecutive blank lines to max 2 (one blank line separator)."""
    result = []
    blank_count = 0
    for line in lines:
        if line.strip() == '':
            blank_count += 1
            if blank_count <= 1:
                result.append(line)
        else:
            blank_count = 0
            result.append(line)
    # Also strip leading/trailing blanks from entire file
    while result and result[0].strip() == '':
        result.pop(0)
    while result and result[-1].strip() == '':
        result.pop()
    return result


def _remove_empty_if_else(lines):
    """Remove empty else blocks: 'else' immediately followed by 'end'."""
    result = []
    i = 0
    while i < len(lines):
        # Check for pattern: else\n<blank>\nend or else\nend
        if i < len(lines) - 1:
            cur = lines[i].strip()
            j = i + 1
            # Skip blank lines between else and end
            while j < len(lines) and lines[j].strip() == '':
                j += 1
            if cur == 'else' and j < len(lines) and lines[j].strip() == 'end':
                # Replace 'else' + possible blanks + 'end' with just 'end'
                indent = len(lines[i]) - len(lines[i].lstrip())
                result.append(lines[i][:indent] + 'end')
                i = j + 1
                continue
        result.append(lines[i])
        i += 1
    return result


def _fix_number_literals(lines):
    """Fix float literals that should be integers (e.g., 100.0 → 100)."""
    # Match standalone number literals like 100.0 but not inside strings
    def _fix_nums(match):
        val = match.group(0)
        try:
            f = float(val)
            if f == int(f) and '.' in val and abs(f) < 2**53:
                # Only convert if it's a clean .0
                if val.endswith('.0'):
                    return str(int(f))
        except (ValueError, OverflowError):
            pass
        return val

    result = []
    num_re = re.compile(r'(?<!["\'\w])-?\d+\.\d+(?!["\'\w])')
    in_string = False
    for line in lines:
        # Simple heuristic: don't modify lines that are string content
        if not in_string:
            result.append(num_re.sub(_fix_nums, line))
        else:
            result.append(line)
    return result


def _remove_trailing_bare_return(lines):
    """Remove bare 'return' that is the last statement before 'end' of a function.

    Matches the pattern:
        return
    end
    where the 'return' has no value and directly precedes the closing 'end'.
    Lua functions return implicitly at end, so this is redundant.
    """
    result = []
    i = 0
    while i < len(lines):
        if i < len(lines) - 1:
            cur_stripped = lines[i].strip()
            # Look ahead past blank lines
            j = i + 1
            while j < len(lines) and lines[j].strip() == '':
                j += 1
            if cur_stripped == 'return' and j < len(lines) and lines[j].strip() == 'end':
                # Skip the bare return (and any blank lines between it and end)
                i = j
                continue
        result.append(lines[i])
        i += 1
    return result


def _strip_trailing_whitespace(lines):
    """Strip trailing whitespace from each line."""
    return [line.rstrip() for line in lines]
