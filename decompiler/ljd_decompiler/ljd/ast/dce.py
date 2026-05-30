"""
Dead Store Elimination (DCE) for LJD AST.

Removes assignments like `varN = true` where varN is never subsequently
read in the same function scope. Only removes assignments with pure
(side-effect-free) right-hand sides.

Usage:
    from ljd.ast.dce import eliminate_dead_stores
    count = eliminate_dead_stores(ast)
"""

from collections import defaultdict
from ljd.ast import traverse, nodes


def eliminate_dead_stores(ast):
    """Remove trivially dead variable assignments and self-assignments.

    Returns the number of assignments removed.
    """
    collector = _UseTracker()
    traverse.traverse(collector, ast)

    # Also find self-assignments (slot0 = slot0)
    self_finder = _SelfAssignmentFinder()
    traverse.traverse(self_finder, ast)

    dead = collector._dead_stmts | self_finder._dead_stmts

    if not dead:
        return 0

    cleaner = _StmtCleaner(dead)
    traverse.traverse(cleaner, ast)

    return collector._removed_count + self_finder._removed_count


# ------------------------------------------------------------------ helpers

def _is_temp_var(ident):
    """Return True if *ident* is an unnamed slot or a generated varN name."""
    if not isinstance(ident, nodes.Identifier):
        return False
    if ident.type == nodes.Identifier.T_SLOT:
        return True
    if ident.type == nodes.Identifier.T_LOCAL:
        name = ident.name
        if name and len(name) >= 4 and name[:3] == "var":
            # var0, var1, ..., var999
            return name[3:].isdigit()
    return False


def _is_pure_expr(expr):
    """Return True if *expr* has no side effects and can be safely removed."""
    if expr is None:
        return True
    if isinstance(expr, nodes.Constant):
        return True
    if isinstance(expr, nodes.Primitive):
        return True
    if isinstance(expr, nodes.Identifier):
        return True
    if isinstance(expr, nodes.MULTRES):
        return False
    if isinstance(expr, nodes.Vararg):
        return True
    # Table element access (e.g. pos.y) is pure
    if isinstance(expr, nodes.TableElement):
        return (_is_pure_expr(getattr(expr, 'table', None)) and
                _is_pure_expr(getattr(expr, 'key', None)))
    # Table constructors are pure only if all their contents are pure
    if isinstance(expr, nodes.TableConstructor):
        records = getattr(expr, 'records', None)
        array = getattr(expr, 'array', None)
        if records:
            items = getattr(records, 'contents', [])
            for rec in items:
                if isinstance(rec, nodes.TableRecord):
                    if not _is_pure_expr(rec.key):
                        return False
                    if not _is_pure_expr(rec.value):
                        return False
                elif isinstance(rec, nodes.ArrayRecord):
                    if not _is_pure_expr(rec.value):
                        return False
        if array:
            items = getattr(array, 'contents', [])
            for rec in items:
                if isinstance(rec, nodes.ArrayRecord):
                    if not _is_pure_expr(rec.value):
                        return False
                elif isinstance(rec, nodes.TableRecord):
                    if not _is_pure_expr(rec.key):
                        return False
                    if not _is_pure_expr(rec.value):
                        return False
        return True
    # Unary/binary ops on pure operands are pure
    if isinstance(expr, nodes.UnaryOperator):
        return _is_pure_expr(getattr(expr, 'operand', None))
    if isinstance(expr, nodes.BinaryOperator):
        return (_is_pure_expr(getattr(expr, 'left', None)) and
                _is_pure_expr(getattr(expr, 'right', None)))
    # Everything else (FunctionCall, MethodCall, etc.) is NOT pure
    return False


def _is_pure_assignment(assign):
    """Return True if all RHS expressions in the assignment are pure."""
    exprs = getattr(assign, 'expressions', None)
    if not exprs:
        return True
    for expr in getattr(exprs, 'contents', []):
        if not _is_pure_expr(expr):
            return False
    return True


# -------------------------------------------------- Pass 1: Use tracking

class _UseTracker(traverse.Visitor):
    """Walk the AST, track reads/writes per temp var per function scope.

    After visiting each function, determine which temp-var slots are
    *write-only* (never read) and mark their pure-RHS assignments as dead.
    """

    def __init__(self):
        self._func_stack = []          # per-function scope info
        self._assign_dest_ids = set()  # id(Identifier) nodes that are write targets
        self._dead_stmts = set()       # id(Assignment) nodes to remove
        self._removed_count = 0

    # -- scope management --

    def visit_function_definition(self, node):
        self._func_stack.append({
            "write_map": defaultdict(list),  # slot -> [Assignment node, ...]
            "read_slots": set(),             # slot numbers that are READ
        })

    def leave_function_definition(self, node):
        scope = self._func_stack.pop()
        dead_slots = set(scope["write_map"].keys()) - scope["read_slots"]

        for slot in dead_slots:
            for assign in scope["write_map"][slot]:
                if _is_pure_assignment(assign):
                    # Only remove the whole assignment if ALL destinations are dead
                    all_dead = True
                    for dest in getattr(assign.destinations, 'contents', []):
                        if _is_temp_var(dest):
                            s = dest.slot
                            if s not in dead_slots:
                                all_dead = False
                                break
                        else:
                            all_dead = False
                            break

                    if all_dead:
                        self._dead_stmts.add(id(assign))
                        self._removed_count += 1

    # -- write tracking --

    def visit_assignment(self, node):
        if not self._func_stack:
            return
        scope = self._func_stack[-1]
        for dest in getattr(node.destinations, 'contents', []):
            if _is_temp_var(dest):
                self._assign_dest_ids.add(id(dest))
                scope["write_map"][dest.slot].append(node)

    # -- read tracking --

    def visit_identifier(self, node):
        if not self._func_stack:
            return
        # Skip identifiers that are assignment destinations
        if id(node) in self._assign_dest_ids:
            return
        if _is_temp_var(node):
            self._func_stack[-1]["read_slots"].add(node.slot)


# -------------------------------------------------- Pass 2: Removal

class _StmtCleaner(traverse.Visitor):
    """Remove dead assignment statements from StatementsList containers."""

    def __init__(self, dead_ids):
        self._dead_ids = dead_ids  # set of id(assign_node)

    def visit_statements_list(self, node):
        contents = getattr(node, 'contents', None)
        if contents is None:
            return
        node.contents = [s for s in contents if id(s) not in self._dead_ids]


# ---------------------------------------- Self-assignment detection

def _is_self_assignment(assign):
    """Check if assignment is `x = x` (same slot on both sides)."""
    dests = getattr(assign.destinations, 'contents', [])
    exprs = getattr(assign.expressions, 'contents', [])
    if len(dests) != 1 or len(exprs) != 1:
        return False
    dst = dests[0]
    src = exprs[0]
    if not isinstance(dst, nodes.Identifier) or not isinstance(src, nodes.Identifier):
        return False
    # Same slot number and same type → self-assignment
    if dst.slot == src.slot and dst.slot >= 0:
        return True
    # Same named variable
    if dst.name and src.name and dst.name == src.name:
        return True
    return False


class _SelfAssignmentFinder(traverse.Visitor):
    """Find and mark self-assignments (slot0 = slot0) as dead."""

    def __init__(self):
        self._dead_stmts = set()
        self._removed_count = 0

    def visit_assignment(self, node):
        if _is_self_assignment(node):
            self._dead_stmts.add(id(node))
            self._removed_count += 1
