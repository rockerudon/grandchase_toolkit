#
# ljd/ast/slotrenamer.py — Context-based variable renaming for stripped bytecode
#
# Replaces generic "slotN" names with meaningful names derived from usage context.
# Designed for Grand Chase decompiled scripts but works generically.
#

import ljd.ast.nodes as nodes
import ljd.ast.traverse as traverse


def rename_slots(ast):
    """Post-process AST to rename remaining T_SLOT identifiers."""
    traverse.traverse(_SlotRenamer(), ast)


# ── Heuristic name derivation ──────────────────────────────────────────────

def _name_from_method_call(call_node):
    """Derive a variable name from a method/function call assignment."""
    func = call_node.function

    # obj:Method(...) → method call
    if isinstance(func, nodes.TableElement):
        key = func.key
        if isinstance(key, nodes.Constant) and key.type == nodes.Constant.T_STRING:
            method = key.value
            return _METHOD_NAMES.get(method, _generic_from_method(method))

    # globalFunc(...) → function call
    if isinstance(func, nodes.TableElement):
        key = func.key
        if isinstance(key, nodes.Constant) and key.type == nodes.Constant.T_STRING:
            name = key.value
            return _FUNC_NAMES.get(name, _generic_from_func(name))

    return None


def _generic_from_method(method):
    """Generate a name from a method name like GetPlayer -> player."""
    m = method
    if m.startswith("Get") and len(m) > 3:
        rest = m[3:]
        return rest[0].lower() + rest[1:] if rest else None
    if m.startswith("Find") and len(m) > 4:
        rest = m[4:]
        return rest[0].lower() + rest[1:] if rest else None
    if m.startswith("Create") and len(m) > 6:
        rest = m[6:]
        return rest[0].lower() + rest[1:] if rest else None
    if m.startswith("Check") and len(m) > 5:
        rest = m[5:]
        return rest[0].lower() + rest[1:] if rest else None
    if m.startswith("Set") and len(m) > 3:
        rest = m[3:]
        return (rest[0].lower() + rest[1:] + "Val") if rest else None
    if m.startswith("Add") and len(m) > 3:
        rest = m[3:]
        return rest[0].lower() + rest[1:] if rest else None
    if m.startswith("Remove") and len(m) > 6:
        rest = m[6:]
        return rest[0].lower() + rest[1:] if rest else None
    if m.startswith("Register") and len(m) > 8:
        rest = m[8:]
        return rest[0].lower() + rest[1:] if rest else None
    if m.startswith("Is") and len(m) > 2:
        return m[0].lower() + m[1:]
    if m.startswith("Has") and len(m) > 3:
        return m[0].lower() + m[1:]
    # General fallback: lowercase first char of method name
    if m and m[0].isalpha() and len(m) > 1:
        return m[0].lower() + m[1:]
    return None


def _generic_from_func(name):
    """Generate a name from a global function name."""
    n = name
    if n.startswith("get_") or n.startswith("Get"):
        rest = n.split("_", 1)[-1] if "_" in n else n[3:]
        return rest[0].lower() + rest[1:] if rest else None
    # General fallback
    if n and n[0].isalpha() and len(n) > 1:
        return n[0].lower() + n[1:]
    return None


# Known method → variable name mapping (Grand Chase specific)
_METHOD_NAMES = {
    "GetPlayer":           "Player",
    "GetMonster":          "Monster",
    "GetNPC":              "npc",
    "GetObject":           "obj",
    "GetTarget":           "target",
    "GetDamageBox":        "damageBox",
    "GetIsRight":          "isRight",
    "GetState":            "state",
    "GetHP":               "hp",
    "GetMP":               "mp",
    "GetPosition":         "pos",
    "GetPosX":             "posX",
    "GetPosY":             "posY",
    "GetDistance":          "dist",
    "GetCount":            "count",
    "GetLevel":            "level",
    "GetSkill":            "skill",
    "GetItem":             "item",
    "GetParty":            "party",
    "GetTeam":             "team",
    "GetRoom":             "room",
    "GetMap":              "mapObj",
    "GetSize":             "size",
    "GetName":             "name",
    "GetType":             "typeVal",
    "GetIndex":            "idx",
    "GetValue":            "val",
    "GetResult":           "result",
    "GetDungeonPlayer":    "dungeonPlayer",
    "GetCharacterType":    "charType",
    "GetCharSlot":         "charSlot",
    "GetCharacterIndex":   "charIdx",
    "random":              "rand",
}

_FUNC_NAMES = {
    "pairs":    "k, v",
    "ipairs":   "i, v",
    "next":     "k, v",
    "type":     "t",
    "tostring": "str",
    "tonumber": "num",
    "math.abs": "absVal",
    "math.floor": "floorVal",
    "math.random": "rand",
    "string.format": "formatted",
}


# ── Slot collection per function scope ─────────────────────────────────────

class _SlotInfo:
    """Tracks all Identifier nodes for a given slot in one function scope."""
    __slots__ = ("slot", "nodes", "assigned_from", "used_as_param_0",
                 "is_func_arg", "arg_index", "total_args", "name",
                 "method_calls_on", "used_as_arg_in")

    def __init__(self, slot):
        self.slot = slot
        self.nodes = []
        self.assigned_from = None
        self.used_as_param_0 = False
        self.is_func_arg = False
        self.arg_index = -1
        self.total_args = 0
        self.name = None
        self.method_calls_on = []
        self.used_as_arg_in = []


class _SlotRenamer(traverse.Visitor):
    """Traverses AST, collects slot info per function, then renames."""

    def __init__(self):
        self._func_stack = []   # stack of {slot: _SlotInfo}
        self._n_args = []       # stack of argument count per function

    def _slots(self):
        return self._func_stack[-1] if self._func_stack else {}

    def _get_slot_info(self, slot_num):
        slots = self._slots()
        if slot_num not in slots:
            slots[slot_num] = _SlotInfo(slot_num)
        return slots[slot_num]

    @staticmethod
    def _is_renameable(node):
        """Check if an identifier needs renaming (T_SLOT or unnamed T_LOCAL)."""
        if not isinstance(node, nodes.Identifier):
            return False
        if node.type == nodes.Identifier.T_SLOT:
            return True
        if node.type == nodes.Identifier.T_LOCAL and not node.name:
            return True
        return False

    # -- Function scope -------------------------------------------------------

    def visit_function_definition(self, node):
        self._func_stack.append({})
        n_args = 0
        for i, arg in enumerate(node.arguments.contents):
            if isinstance(arg, nodes.Identifier) and self._is_renameable(arg):
                info = self._get_slot_info(arg.slot)
                info.is_func_arg = True
                info.arg_index = i
                info.nodes.append(arg)
                n_args += 1
            elif isinstance(arg, nodes.Identifier):
                n_args += 1
        self._n_args.append(n_args)

    def leave_function_definition(self, node):
        if not self._func_stack:
            return
        slots = self._func_stack.pop()
        n_args = self._n_args.pop() if self._n_args else 0
        for info in slots.values():
            info.total_args = n_args

        # Determine and apply names in slot order (merged phases)
        used_names = set()
        for info in sorted(slots.values(), key=lambda x: x.slot):
            name = _determine_name(info, used_names)
            if name:
                info.name = name
                used_names.add(name)
                for nd in info.nodes:
                    nd.name = info.name
                    nd.type = nodes.Identifier.T_LOCAL

    # -- Collect slot usage ---------------------------------------------------

    def visit_identifier(self, node):
        if not self._func_stack:
            return
        if self._is_renameable(node):
            info = self._get_slot_info(node.slot)
            info.nodes.append(node)

    def visit_assignment(self, node):
        if not self._func_stack:
            return
        dests = node.destinations.contents
        exprs = node.expressions.contents
        for i, dest in enumerate(dests):
            if not isinstance(dest, nodes.Identifier):
                continue
            if not self._is_renameable(dest):
                continue
            info = self._get_slot_info(dest.slot)
            if i < len(exprs):
                rhs = exprs[i]
                if info.assigned_from is None:
                    info.assigned_from = rhs

    def visit_function_call(self, node):
        """Track method calls on slots and slots used as arguments."""
        if not self._func_stack:
            return
        func = node.function
        if not isinstance(func, nodes.TableElement):
            return
        base = func.table
        key = func.key
        if not self._is_renameable(base):
            return
        if not isinstance(key, nodes.Constant) or key.type != nodes.Constant.T_STRING:
            return
        method_name = key.value
        args = node.arguments.contents if hasattr(node.arguments, 'contents') else []
        is_method = False
        if len(args) >= 1:
            first_arg = args[0]
            if isinstance(first_arg, nodes.Identifier) and hasattr(first_arg, 'slot'):
                if first_arg.slot == base.slot:
                    is_method = True
        info = self._get_slot_info(base.slot)
        info.method_calls_on.append(method_name)
        # Track slots passed as arguments
        for i, arg in enumerate(args):
            if self._is_renameable(arg):
                if is_method and i == 0:
                    continue
                param_idx = i - 1 if is_method else i
                arg_info = self._get_slot_info(arg.slot)
                arg_info.used_as_arg_in.append((method_name, param_idx))


# -- Name determination logic -------------------------------------------------

def _determine_name(info, used_names):
    """Determine the best name for a slot based on context."""
    if info.is_func_arg:
        return _name_for_arg(info, used_names)

    rhs = info.assigned_from
    if rhs is not None:
        name = _name_from_rhs(rhs)
        if name:
            return _make_unique(name, used_names)

    if info.method_calls_on:
        name = _name_from_method_calls_on(info.method_calls_on)
        if name:
            return _make_unique(name, used_names)

    if info.used_as_arg_in:
        name = _name_from_param_usage(info.used_as_arg_in)
        if name:
            return _make_unique(name, used_names)

    base = "local" + str(info.slot)
    return _make_unique(base, used_names)


def _name_for_arg(info, used_names):
    idx = info.arg_index
    name = "ARG_" + str(idx)
    return _make_unique(name, used_names)


def _name_from_rhs(rhs):
    """Derive a name from the right-hand side of an assignment."""
    if isinstance(rhs, nodes.FunctionCall):
        name = _name_from_method_call(rhs)
        if name:
            return name

    if isinstance(rhs, nodes.TableElement):
        key = rhs.key
        if isinstance(key, nodes.Constant) and key.type == nodes.Constant.T_STRING:
            val = key.value
            if val and val[0].isalpha():
                if len(val) > 20:
                    val = val[:20]
                return val[0].lower() + val[1:]

    if isinstance(rhs, nodes.BinaryOperator):
        name = _extract_method_from_expr(rhs)
        if name:
            return name
        return None

    if isinstance(rhs, nodes.UnaryOperator):
        inner = _extract_method_from_expr(rhs.operand)
        if inner and rhs.type == nodes.UnaryOperator.T_NOT:
            if inner.startswith("is") and len(inner) > 2 and inner[2].isupper():
                return "not" + inner[0].upper() + inner[1:]
            return "not_" + inner
        if inner and rhs.type == nodes.UnaryOperator.T_MINUS:
            return "neg" + inner[0].upper() + inner[1:]
        if inner:
            return inner
        if rhs.type == nodes.UnaryOperator.T_LENGTH_OPERATOR:
            return "len"
        return None

    if isinstance(rhs, nodes.TableConstructor):
        return "tbl"

    if isinstance(rhs, nodes.Primitive):
        if rhs.type in (nodes.Primitive.T_TRUE, nodes.Primitive.T_FALSE):
            return "flag"
        return None

    if isinstance(rhs, nodes.Identifier):
        if rhs.name:
            n = rhs.name
            if n.startswith("_ARG_"):
                return "argCopy"
            if len(n) > 20:
                n = n[:20]
            if n[0].isupper():
                return n[0].lower() + n[1:]
            return n
        return None

    if isinstance(rhs, nodes.Constant):
        return None

    return None


def _extract_method_from_expr(node):
    """Recursively search an expression tree for a method/function call."""
    if isinstance(node, nodes.FunctionCall):
        return _name_from_method_call(node)
    if isinstance(node, nodes.BinaryOperator):
        name = _extract_method_from_expr(node.left)
        if name:
            return name
        return _extract_method_from_expr(node.right)
    if isinstance(node, nodes.UnaryOperator):
        return _extract_method_from_expr(node.operand)
    if isinstance(node, nodes.Identifier) and node.name:
        n = node.name
        if not n.startswith("_ARG_") and not n.startswith("local") and n[0].isalpha():
            return n[0].lower() + n[1:] + "Calc"
    return None


def _make_unique(name, used_names):
    if name not in used_names:
        return name
    for i in range(2, 100):
        candidate = name + str(i)
        if candidate not in used_names:
            return candidate


# -- Method-call-target inference ---------------------------------------------

_METHOD_TO_ENTITY = {}

for _m in ("PlaySound", "PlaySoundLoop", "StopSound", "StopSoundAll",
           "SetPosition", "SetPosX", "SetPosY", "GetPosX", "GetPosY",
           "GetPosition", "GetIsRight", "SetIsRight",
           "AddDamage", "AddDamageNoLatency", "AddDamageRange",
           "SetAction", "GetAction", "SetState", "GetState",
           "SetAnimation", "PlayAnimation", "StopAnimation",
           "SetGravity", "SetSpeed", "SetSpeedX", "SetSpeedY",
           "GetSpeedX", "GetSpeedY",
           "SetInvincible", "SetSuperArmor", "SetNoInput",
           "IsDead", "IsAlive", "GetHP", "GetMP", "SetHP", "SetMP",
           "AddHP", "AddMP", "GetMaxHP", "GetMaxMP",
           "GetLevel", "GetExp",
           "SetVisible", "IsVisible", "SetAlpha",
           "GetCharacterType", "GetCharSlot", "GetCharacterIndex",
           "SetScale", "GetScale",
           "GetDistance", "GetDistanceX", "GetDistanceY",
           "IsOnGround", "SetOnGround",
           "AddBuff", "RemoveBuff", "HasBuff",
           "SetSkill", "GetSkill", "UseSkill",
           "GetTeam", "GetParty"):
    _METHOD_TO_ENTITY[_m] = "Player"

for _m in ("SetDamageBox", "GetDamageBox", "ClearDamageBox",
           "SetDamageBoxSize", "SetDamageBoxOffset",
           "SetHitCount", "GetHitCount",
           "SetDamageRate", "GetDamageRate"):
    _METHOD_TO_ENTITY[_m] = "damageBox"

for _m in ("SetEffect", "PlayEffect", "StopEffect", "RemoveEffect",
           "SetEffectPosition", "SetEffectScale",
           "CreateEffect", "DestroyEffect"):
    _METHOD_TO_ENTITY[_m] = "effect"

for _m in ("SetText", "GetText", "SetFontSize", "SetFontColor",
           "Show", "Hide", "SetEnable", "IsEnabled",
           "SetSize", "GetSize", "SetPos", "GetPos",
           "AddChild", "RemoveChild", "GetChild",
           "SetImage", "SetTexture", "SetColor",
           "SetTooltip", "SetCallback"):
    _METHOD_TO_ENTITY[_m] = "widget"

for _m in ("Start", "Stop", "Reset", "IsRunning", "GetTime", "SetTime"):
    _METHOD_TO_ENTITY[_m] = "timer"


def _name_from_method_calls_on(method_list):
    """Infer entity name from methods called ON a slot."""
    if not method_list:
        return None
    votes = {}
    for method in method_list:
        entity = _METHOD_TO_ENTITY.get(method)
        if entity:
            votes[entity] = votes.get(entity, 0) + 1
    if votes:
        return max(votes, key=votes.get)
    first = method_list[0]
    name = _generic_from_method(first)
    if name:
        return name
    return "obj"


# -- Parameter-position naming ------------------------------------------------

_PARAM_POSITION_NAMES = {
    "AddParticle":                          {0: "particleName", 1: "offsetX", 2: "offsetY"},
    "AddParticleNoDirection":               {0: "particleName", 1: "offsetX", 2: "offsetY"},
    "AddParticlePos":                       {0: "particleName", 1: "particleX", 2: "particleY"},
    "AddParticleNoDirectionPos":            {0: "particleName", 1: "particleX", 2: "particleY"},
    "AddParticleNoDirectionPosWithTrace":   {0: "particleName", 1: "particleX", 2: "particleY"},
    "AddParticlePosWithTrace":              {0: "particleName", 1: "particleX", 2: "particleY"},
    "AddTraceParticleToBone":               {0: "particleName", 1: "boneName"},
    "AddTraceParticleOffset":               {0: "particleName", 1: "traceOffX", 2: "traceOffY"},
    "AddParticleToChildMeshBone":           {0: "particleName", 1: "boneName"},
    "SetPosition":                          {0: "posX", 1: "posY"},
    "SetX":                                 {0: "posX"},
    "SetY":                                 {0: "posY"},
    "SetSpeedX":                            {0: "speedX"},
    "SetSpeedY":                            {0: "speedY"},
    "AddDamageWithLocateAngle":             {0: "dmgType", 1: "locateX", 2: "locateY", 3: "angle"},
    "AddDamageWithLocate":                  {0: "dmgType", 1: "locateX", 2: "locateY"},
    "AddDamageWithSpeed":                   {0: "dmgType", 1: "dmgSpeedX", 2: "dmgSpeedY"},
    "AddDamageWithStatic":                  {0: "dmgType", 1: "staticX", 2: "staticY"},
    "AddDamageWithAngle":                   {0: "dmgType", 1: "dmgAngle"},
    "AddDamageTarget":                      {0: "targetIdx"},
    "AddDamage":                            {0: "dmgType"},
    "SetMapTempValue":                      {0: "mapKey", 1: "mapTempVal"},
    "SetTempValue":                         {0: "tempKey", 1: "tempVal"},
    "SetNowValue":                          {0: "nowKey", 1: "nowVal"},
    "SetMagicEffect":                       {0: "effectName", 1: "effectParam"},
    "GetPlayer":                            {0: "playerSlot"},
    "GetPlayerByUID":                       {0: "uid"},
    "GetMonster":                           {0: "monsterSlot"},
    "SetChildMeshFrame":                    {0: "meshName", 1: "meshFrame"},
    "SetDownDelay":                         {0: "delay"},
    "StartAttack":                          {0: "attackName"},
    "SetPlayerHP":                          {0: "hpVal"},
    "CheckEnemyInRange":                    {0: "rangeParam"},
    "SyncRandomByIndex":                    {0: "syncIdx"},
    "SyncRandom":                           {0: "syncSeed"},
}


def _name_from_param_usage(used_as_arg_in):
    """Derive name from how a slot is used as an argument to method calls."""
    if not used_as_arg_in:
        return None
    votes = {}
    for method_name, param_idx in used_as_arg_in:
        pos_map = _PARAM_POSITION_NAMES.get(method_name)
        if pos_map and param_idx in pos_map:
            name = pos_map[param_idx]
            votes[name] = votes.get(name, 0) + 1
        else:
            if method_name.startswith("Set") and param_idx == 0 and len(method_name) > 3:
                rest = method_name[3:]
                derived = rest[0].lower() + rest[1:]
                votes[derived] = votes.get(derived, 0) + 1
    if votes:
        return max(votes, key=votes.get)
    methods = {}
    for method_name, _ in used_as_arg_in:
        methods[method_name] = methods.get(method_name, 0) + 1
    if methods:
        most_common = max(methods, key=methods.get)
        if "Particle" in most_common:
            return "particleParam"
        if "Damage" in most_common:
            return "dmgParam"
        if "Pos" in most_common or "Position" in most_common:
            return "posParam"
        if "Speed" in most_common:
            return "speedParam"
        if "Effect" in most_common:
            return "effectParam"
    return None
