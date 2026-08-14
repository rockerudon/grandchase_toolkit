"""Stable names for stripped-bytecode upvalues.

LJD traditionally lets an unnamed upvalue inherit the textual name of a slot
with the same numeric index.  Slot indexes and upvalue indexes are separate
register spaces, so this can turn a captured counter into ``Player`` or a
function argument.  This pass follows LuaJIT's upvalue-reference table and
gives the captured parent slot and every child reference the same safe name.
"""

import ljd.ast.nodes as nodes
import ljd.ast.traverse as traverse


LOCAL_REFERENCE_FLAG = 0x8000
# LuaJIT uses bit 15 for "captures parent local" and bit 14 for the
# immutable flag.  Only the lower 14 bits are the actual register index.
REFERENCE_INDEX_MASK = 0x3FFF


def rename_upvalues(ast):
    traverse.traverse(_UpvalueRenamer(), ast)


class _FunctionInfo:
    def __init__(self):
        self.identifiers_by_slot = {}
        self.captured_names = {}
        self.upvalue_names = {}
        self.upvalue_nodes = []


class _UpvalueRenamer(traverse.Visitor):
    def __init__(self):
        self._stack = []

    def visit_function_definition(self, node):
        parent = self._stack[-1] if self._stack else None
        info = _FunctionInfo()

        references = getattr(node, "_upvalues", None) or []
        for upvalue_index, encoded_reference in enumerate(references):
            if encoded_reference & LOCAL_REFERENCE_FLAG:
                parent_slot = encoded_reference & REFERENCE_INDEX_MASK
                name = "capturedLocal" + str(parent_slot)
                if parent is not None:
                    parent.captured_names[parent_slot] = name
            else:
                parent_upvalue = encoded_reference & REFERENCE_INDEX_MASK
                if parent is not None:
                    name = parent.upvalue_names.get(
                        parent_upvalue,
                        "capturedUpvalue" + str(parent_upvalue),
                    )
                else:
                    name = "capturedUpvalue" + str(parent_upvalue)

            info.upvalue_names[upvalue_index] = name

        self._stack.append(info)

    def leave_function_definition(self, node):
        info = self._stack.pop()

        for slot, name in info.captured_names.items():
            for identifier in info.identifiers_by_slot.get(slot, []):
                identifier.name = name
                identifier.type = nodes.Identifier.T_LOCAL

        for identifier in info.upvalue_nodes:
            identifier.name = info.upvalue_names.get(
                identifier.slot,
                "capturedUpvalue" + str(identifier.slot),
            )

    def visit_identifier(self, node):
        if not self._stack:
            return

        info = self._stack[-1]
        if node.type == nodes.Identifier.T_UPVALUE:
            info.upvalue_nodes.append(node)
            return

        if node.type in (nodes.Identifier.T_SLOT, nodes.Identifier.T_LOCAL):
            info.identifiers_by_slot.setdefault(node.slot, []).append(node)
