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
    lines = _join_wrapped_if_headers(lines)
    lines = _repair_dangling_local_declarations(lines)
    # Outer and inner empty warps can overlap.  Each pass exposes the next
    # nested body, so iterate to a small fixed point instead of leaving the
    # inner return in the outer block.
    for _ in range(8):
        recovered = _recover_unresolved_conditional_warps(lines)
        if recovered == lines:
            break
        lines = recovered
    lines = _repair_split_early_return_blocks(lines)
    lines = _repair_statements_after_return(lines)
    lines = _remove_block_annotations(lines)
    lines = _remove_self_assignments(lines)
    lines = _repair_speed_multiplier_artifacts(lines)
    lines = _fix_return_trailing_space(lines)
    lines = _collapse_blank_lines(lines)
    lines = _remove_empty_if_else(lines)
    lines = _fix_number_literals(lines)
    lines = _strip_trailing_whitespace(lines)
    return '\n'.join(lines)


def _indent(line):
    """Return the exact leading whitespace of *line*."""
    return line[:len(line) - len(line.lstrip())]


def _join_wrapped_if_headers(lines):
    """Join comparison tails that the writer wrapped onto a second line.

    Some KL conditional warps are emitted as::

        if Monster:IsTarget()
         == true then

    Besides being invalid Lua, this prevents the unresolved-warp recovery
    below from recognizing the empty conditional and restoring its body.
    Only continuation lines beginning with a comparison operator are joined,
    so ordinary multiline statements remain untouched.
    """
    result = []
    comparison_tail = re.compile(
        r'^\s*(?:(==|~=|<=|>=|<|>)\s+.+\s+)?then\s*$'
    )

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith('if ') and not stripped.endswith(' then') \
                and i + 1 < len(lines):
            tail = lines[i + 1]
            if comparison_tail.match(tail):
                result.append(line.rstrip() + ' ' + tail.strip())
                i += 2
                continue
        result.append(line)
        i += 1

    return result


def _repair_dangling_local_declarations(lines):
    """Repair local-name tails detached from a function declaration.

    Register recovery can occasionally emit the tail of a local declaration
    as the first statement of a function::

        Player_Action[MID_EXAMPLE] = function (ARG_0, ARG_1)
            , player2, player3

    Besides being invalid Lua, the leading comma makes every later cleanup
    fail.  Restrict the repair to the first non-blank line after a function
    header so a malformed expression elsewhere is never silently rewritten.
    """
    result = list(lines)
    dangling_re = re.compile(
        r'^(\s*),\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*$'
    )

    for i, line in enumerate(result):
        match = dangling_re.match(line)
        if not match:
            continue

        previous = i - 1
        while previous >= 0 and result[previous].strip() == '':
            previous -= 1
        if previous < 0:
            continue

        header = result[previous].strip()
        if not re.search(r'\bfunction\s*\([^)]*\)\s*$', header):
            continue

        result[i] = match.group(1) + 'local ' + match.group(2)

    return result


def _recover_unresolved_conditional_warps(lines):
    """Recover the small KL short-circuit fragments left by the unwarper.

    KL/LuaJIT uses ISTC followed by JMP for ``a or b``.  When extraction of
    an outer if has already moved the jump target, LJD can leave an empty raw
    warp immediately before the if for ``b``.  The preserved opcode makes the
    repair unambiguous.  Plain ISF/comparison leftovers are the complementary
    case: the statements up to the enclosing branch boundary are the missing
    body of the empty if.

    Unknown layouts are deliberately left marked for manual review.
    """
    result = list(lines)
    marker_re = re.compile(
        r'^\s*-- unresolved conditional warp(?: for slot\d+)? '
        r'\((\w+) at bytecode \d+\)\s*$'
    )

    i = 0
    while i + 2 < len(result):
        header = result[i]
        stripped = header.strip()
        if not (stripped.startswith('if ') and stripped.endswith(' then')):
            i += 1
            continue

        indent = _indent(header)
        marker_i = i + 1
        while marker_i < len(result) and result[marker_i].strip() == '':
            marker_i += 1
        if marker_i >= len(result):
            break

        marker = marker_re.match(result[marker_i])
        if not marker:
            i += 1
            continue

        end_i = marker_i + 1
        while end_i < len(result) and result[end_i].strip() == '':
            end_i += 1
        if end_i >= len(result) or result[end_i].strip() != 'end' \
                or _indent(result[end_i]) != indent:
            i += 1
            continue

        opcode = marker.group(1)
        condition = stripped[3:-5].strip()

        if opcode == 'ISTC' and condition.startswith('not '):
            # Locate the RHS condition.  Alias assignments emitted by slot
            # recovery may sit between both halves; preserve them before the
            # newly combined if.
            next_if = end_i + 1
            while next_if < len(result):
                candidate = result[next_if]
                if candidate.strip() == '':
                    next_if += 1
                    continue
                if _indent(candidate) != indent:
                    break
                candidate_s = candidate.strip()
                if candidate_s.startswith('if ') and candidate_s.endswith(' then'):
                    break
                if re.match(r'^[A-Za-z_]\w*\s*=\s*.+$', candidate_s):
                    next_if += 1
                    continue
                break

            if next_if < len(result):
                rhs_header = result[next_if]
                rhs_s = rhs_header.strip()
                if _indent(rhs_header) == indent \
                        and rhs_s.startswith('if ') and rhs_s.endswith(' then'):
                    lhs = condition[4:].strip()
                    rhs = rhs_s[3:-5].strip()
                    between = result[end_i + 1:next_if]
                    # ``a or b and c`` would change the VM control flow. ISTC
                    # short-circuits only the first RHS operand; any following
                    # AND chain applies to the combined ``a or b`` result.
                    if ' and ' in rhs:
                        first_rhs, remainder = rhs.split(' and ', 1)
                        combined = ('(' + lhs + ' or ' + first_rhs.strip()
                                    + ') and ' + remainder)
                    else:
                        combined = lhs + ' or ' + rhs
                    result[i:next_if + 1] = between + [
                        indent + 'if ' + combined + ' then'
                    ]
                    i += len(between) + 1
                    continue

        elif opcode in ('ISF', 'IST', 'ISGE', 'ISGT', 'ISLE', 'ISLT',
                        'ISEQV', 'ISNEV', 'ISEQP', 'ISNEP', 'ISEQN',
                        'ISNEN'):
            # The raw test is an empty if followed by the body that was split
            # out.  Its enclosing elseif/else/end has a smaller indentation.
            body_end = end_i + 1
            while body_end < len(result):
                line = result[body_end]
                if line.strip() == '':
                    body_end += 1
                    continue
                if len(_indent(line)) < len(indent):
                    break
                body_end += 1
                # A return at the conditional's own indentation is an exact
                # control-flow boundary.  Consuming statements after it can
                # swallow the next independent branch and produce unbalanced
                # Lua (seen in Void3 Destroyer2 and Tracker).
                if line.strip() == 'return' and _indent(line) == indent:
                    break

            body = result[end_i + 1:body_end]
            if any(line.strip() for line in body):
                shifted = [indent + '\t' + line[len(indent):]
                           if line.strip() else line for line in body]
                result[i:body_end] = [header] + shifted + [indent + 'end']
                i += len(shifted) + 2
                continue

        i += 1

    return result


def _repair_split_early_return_blocks(lines):
    """Move a prematurely emitted ``end`` past its early-return tail.

    Level-1 KL output sometimes represents one guarded block as an empty
    outer test followed by an inner test.  Recovering the inner test first
    can leave ``end; statement; return; next statement`` at one indentation.
    Lua forbids statements after a return in the same block; the statement
    and return are in fact the tail of the just-closed outer conditional.
    """
    result = list(lines)
    i = 0
    while i + 3 < len(result):
        if result[i].strip() != 'end':
            i += 1
            continue
        indent = _indent(result[i])
        j = i + 1
        while j < len(result) and result[j].strip() == '':
            j += 1
        if j >= len(result) or _indent(result[j]) != indent \
                or result[j].strip() in ('end', 'else', 'elseif'):
            i += 1
            continue

        return_i = j
        while return_i < len(result) and _indent(result[return_i]) == indent:
            if result[return_i].strip() == 'return':
                break
            if result[return_i].strip().startswith(('if ', 'function ')):
                break
            return_i += 1
        if return_i >= len(result) or result[return_i].strip() != 'return':
            i += 1
            continue

        next_i = return_i + 1
        while next_i < len(result) and result[next_i].strip() == '':
            next_i += 1
        if next_i >= len(result) or _indent(result[next_i]) != indent \
                or result[next_i].strip() in ('end', 'else', 'elseif'):
            i += 1
            continue

        for k in range(j, return_i + 1):
            if result[k].strip():
                result[k] = indent + '\t' + result[k][len(indent):]
        closing = result.pop(i)
        return_i -= 1
        result.insert(return_i + 1, closing)
        i = return_i + 2

    return result


def _repair_statements_after_return(lines):
    """Close a branch before statements emitted after its bare return.

    Lua requires ``return`` to be the final statement of its block.  If the
    unwarper leaves sibling statements before the matching ``end``, move that
    end directly after the return and dedent the siblings.
    """
    result = list(lines)
    i = 0
    while i + 2 < len(result):
        if result[i].strip() != 'return':
            i += 1
            continue
        indent = _indent(result[i])
        j = i + 1
        while j < len(result) and not result[j].strip():
            j += 1
        if j >= len(result) or result[j].strip() == 'end' \
                or _indent(result[j]) != indent:
            i += 1
            continue
        end_i = j
        while end_i < len(result):
            if result[end_i].strip() == 'end' \
                    and _indent(result[end_i]) == indent[:-1]:
                break
            if len(_indent(result[end_i])) < max(0, len(indent) - 1):
                break
            end_i += 1
        if end_i >= len(result) or result[end_i].strip() != 'end':
            i += 1
            continue
        closing = result.pop(end_i)
        result.insert(i + 1, closing)
        for k in range(i + 2, end_i + 1):
            if result[k].strip() and result[k].startswith('\t'):
                result[k] = result[k][1:]
        i += 2
    return result


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


def _repair_speed_multiplier_artifacts(lines):
    """Repair KL arithmetic opcodes decoded as addition on player speeds.

    In the Classic KL bytecode, damping/acceleration expressions such as
    ``x_Speed = x_Speed * 0.95`` are exposed by the legacy opcode table as
    ADDVN.  The resulting additions move a player across most of the stage in
    one tick.  Real additive impulses in these scripts are below 0.1, whereas
    the misdecoded multiplier factors range from 0.1 through roughly 1.1.
    Restrict the repair to self-referential X/Y speed assignments.
    """
    result = []
    speed_factor_re = re.compile(
        r'^(\s*)([A-Za-z_]\w*)\.([xXyY]_Speed)\s*=\s*'
        r'\2\.\3\s*\+\s*((?:0\.[1-9]\d*|1\.\d+))\s*$'
    )

    for line in lines:
        match = speed_factor_re.match(line)
        if match:
            result.append(
                match.group(1) + match.group(2) + '.' + match.group(3)
                + ' = ' + match.group(2) + '.' + match.group(3)
                + ' * ' + match.group(4)
            )
        else:
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
            if cur_stripped == 'return' and j < len(lines) \
                    and lines[j].strip() == 'end' \
                    and len(_indent(lines[i])) == len(_indent(lines[j])) + 1:
                # Skip the bare return (and any blank lines between it and end)
                i = j
                continue
        result.append(lines[i])
        i += 1
    return result


def _strip_trailing_whitespace(lines):
    """Strip trailing whitespace from each line."""
    return [line.rstrip() for line in lines]
