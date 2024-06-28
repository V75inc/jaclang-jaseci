"""Core constructs for Jac Language."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pickle import dumps
from re import IGNORECASE, compile
from typing import (
    Callable,
    Optional,
    Union,
    cast,
)

from bson import ObjectId

from jaclang.compiler.constant import EdgeDir
from jaclang.core.architype import (
    AnchorAccess,
    Architype as _Architype,
    ObjectAnchor as _ObjectAnchor,
    ObjectType,
)
from jaclang.core.utils import collect_node_connections


GENERIC_ID_REGEX = compile(r"^(g|n|e|w):([^:]*):([a-f\d]{24})$", IGNORECASE)
NODE_ID_REGEX = compile(r"^n:([^:]*):([a-f\d]{24})$", IGNORECASE)
EDGE_ID_REGEX = compile(r"^e:([^:]*):([a-f\d]{24})$", IGNORECASE)
WALKER_ID_REGEX = compile(r"^w:([^:]*):([a-f\d]{24})$", IGNORECASE)


@dataclass(eq=False)
class ObjectAnchor(_ObjectAnchor):
    """Object Anchor."""

    id: ObjectId = field(default_factory=ObjectId)
    root: Optional[ObjectId] = None
    access: AnchorAccess[ObjectId] = field(default_factory=AnchorAccess[ObjectId])
    architype: Optional[Architype] = None

    @classmethod
    def ref(cls, ref_id: str) -> Optional[ObjectAnchor]:
        """Return ObjectAnchor instance if ."""
        if match := GENERIC_ID_REGEX.search(ref_id):
            return cls(
                type=ObjectType(match.group(1)),
                name=match.group(2),
                id=ObjectId(match.group(3)),
            )
        return None

    def sync(self, node: Optional["NodeAnchor"] = None) -> Optional[Architype]:
        """Retrieve the Architype from db and return."""
        if architype := self.architype:
            return architype

        from jaclang.core.context import ExecutionContext

        jsrc = ExecutionContext.get().datasource
        anchor = jsrc.find_one(self.id)

        if anchor and (node or self).is_allowed(anchor):
            self.__dict__.update(anchor.__dict__)

        return self.architype

    def allocate(self) -> None:
        """Allocate hashes and memory."""
        from jaclang.core.context import ExecutionContext

        jctx = ExecutionContext.get()
        self.root = jctx.root.id
        jctx.datasource.set(self, True)

    def is_allowed(self, to: Union[ObjectAnchor, Architype]) -> bool:
        """Access validation."""
        from jaclang.core.context import ExecutionContext

        jctx = ExecutionContext.get()
        jroot = jctx.root
        to = to._jac_ if isinstance(to, Architype) else to
        to.current_access_level = None

        if jroot == jctx.super_root or jroot.id == to.root:
            to.current_access_level = 1
            return True

        if (to_access := to.access).all:
            to.current_access_level = to_access.all - 1
            return True

        if self.current_access_level and self.current_access_level > -1:
            whitelist, has_access, level = to_access.nodes.check(self.id)
            if not whitelist and not has_access:
                to.current_access_level = None
                return False
            elif whitelist and has_access and to.current_access_level is None:
                to.current_access_level = level

            if (architype := self.architype) and (
                access_type := to_access.types.get(architype.__class__)
            ):
                whitelist, has_access, level = access_type.check(self.id)
                if not whitelist and not has_access:
                    to.current_access_level = None
                    return False
                elif whitelist and has_access and to.current_access_level is None:
                    to.current_access_level = level

            whitelist, has_access, level = to_access.roots.check(jroot.id)
            if not whitelist and not has_access:
                to.current_access_level = None
                return False
            elif whitelist and has_access and to.current_access_level is None:
                to.current_access_level = level

            if to.root and (to_root := jctx.datasource.find_one(to.root)):
                whitelist, has_access, level = to_root.access.roots.check(jroot.id)
                if not whitelist and not has_access:
                    to.current_access_level = None
                    return False
                elif whitelist and has_access and to.current_access_level is None:
                    to.current_access_level = level

        return to.current_access_level is not None

    def serialize(self) -> dict[str, object]:
        data = asdict(self)
        data.pop("connected", None)
        data.pop("current_access_level", None)
        data.pop("persistent", None)
        data.pop("hash", None)
        return data


@dataclass(eq=False)
class NodeAnchor(ObjectAnchor):
    """Node Anchor."""

    type: ObjectType = ObjectType.node
    architype: Optional[NodeArchitype] = None
    edges: list[EdgeAnchor] = field(default_factory=list)

    @classmethod
    def ref(cls, ref_id: str) -> Optional[NodeAnchor]:
        """Return NodeAnchor instance if existing."""
        if match := NODE_ID_REGEX.search(ref_id):
            return cls(
                name=match.group(1),
                id=ObjectId(match.group(2)),
            )
        return None

    def _save(self) -> None:
        from jaclang.core.context import ExecutionContext

        jsrc = ExecutionContext.get().datasource

        for edge in self.edges:
            edge.save()

        jsrc.set(self)

    def save(self) -> None:
        """Save Anchor."""
        if self.architype:
            if not self.connected:
                self.connected = True
                self.hash = hash(dumps(self))
                self._save()
            elif self.current_access_level == 1 and self.hash != (
                _hash := hash(dumps(self))
            ):
                self.hash = _hash
                self._save()

    def destroy(self) -> None:
        """Delete Anchor."""
        if self.architype and self.current_access_level == 1:
            from jaclang.core.context import ExecutionContext

            jsrc = ExecutionContext.get().datasource
            for edge in self.edges:
                edge.destroy()

            jsrc.remove(self)

    def sync(self, node: Optional["NodeAnchor"] = None) -> Optional[NodeArchitype]:
        """Retrieve the Architype from db and return."""
        return cast(Optional[NodeArchitype], super().sync(node))

    def unsync(self) -> NodeAnchor:
        """Generate unlinked anchor."""
        return NodeAnchor(name=self.name, id=self.id)

    def connect_node(self, nd: NodeAnchor, edg: EdgeAnchor) -> None:
        """Connect a node with given edge."""
        edg.attach(self, nd)

    def get_edges(
        self,
        dir: EdgeDir,
        filter_func: Optional[Callable[[list[EdgeArchitype]], list[EdgeArchitype]]],
        target_obj: Optional[list[NodeArchitype]],
    ) -> list[EdgeArchitype]:
        """Get edges connected to this node."""
        ret_edges: list[EdgeArchitype] = []
        for anchor in self.edges:
            if (
                (architype := anchor.sync())
                and (source := anchor.source)
                and (target := anchor.target)
                and (not filter_func or filter_func([architype]))
            ):
                src_arch = source.sync()
                trg_arch = target.sync()

                if (
                    dir in [EdgeDir.OUT, EdgeDir.ANY]
                    and self == source
                    and trg_arch
                    and (not target_obj or trg_arch in target_obj)
                    and source.is_allowed(target)
                ):
                    ret_edges.append(architype)
                if (
                    dir in [EdgeDir.IN, EdgeDir.ANY]
                    and self == target
                    and src_arch
                    and (not target_obj or src_arch in target_obj)
                    and target.is_allowed(source)
                ):
                    ret_edges.append(architype)
        return ret_edges

    def edges_to_nodes(
        self,
        dir: EdgeDir,
        filter_func: Optional[Callable[[list[EdgeArchitype]], list[EdgeArchitype]]],
        target_obj: Optional[list[NodeArchitype]],
    ) -> list[NodeArchitype]:
        """Get set of nodes connected to this node."""
        ret_edges: list[NodeArchitype] = []
        for anchor in self.edges:
            if (
                (architype := anchor.sync())
                and (source := anchor.source)
                and (target := anchor.target)
                and (not filter_func or filter_func([architype]))
            ):
                src_arch = source.sync()
                trg_arch = target.sync()

                if (
                    dir in [EdgeDir.OUT, EdgeDir.ANY]
                    and self == source
                    and trg_arch
                    and (not target_obj or trg_arch in target_obj)
                    and source.is_allowed(target)
                ):
                    ret_edges.append(trg_arch)
                if (
                    dir in [EdgeDir.IN, EdgeDir.ANY]
                    and self == target
                    and src_arch
                    and (not target_obj or src_arch in target_obj)
                    and target.is_allowed(source)
                ):
                    ret_edges.append(src_arch)
        return ret_edges

    def gen_dot(self, dot_file: Optional[str] = None) -> str:
        """Generate Dot file for visualizing nodes and edges."""
        visited_nodes: set[NodeAnchor] = set()
        connections: set[tuple[NodeArchitype, NodeArchitype, str]] = set()
        unique_node_id_dict = {}

        collect_node_connections(self, visited_nodes, connections)
        dot_content = 'digraph {\nnode [style="filled", shape="ellipse", fillcolor="invis", fontcolor="black"];\n'
        for idx, i in enumerate([nodes_.architype for nodes_ in visited_nodes]):
            unique_node_id_dict[i] = (i.__class__.__name__, str(idx))
            dot_content += f'{idx} [label="{i}"];\n'
        dot_content += 'edge [color="gray", style="solid"];\n'

        for pair in list(set(connections)):
            dot_content += (
                f"{unique_node_id_dict[pair[0]][1]} -> {unique_node_id_dict[pair[1]][1]}"
                f' [label="{pair[2]}"];\n'
            )
        if dot_file:
            with open(dot_file, "w") as f:
                f.write(dot_content + "}")
        return dot_content + "}"

    def spawn_call(self, walk: WalkerAnchor) -> WalkerArchitype:
        """Invoke data spatial call."""
        return walk.spawn_call(self)

    def __getstate__(self) -> dict[str, object]:
        """Override getstate for pickle and shelve."""
        state = super().__getstate__()
        state["edges"] = [edge.unsync() for edge in self.edges]
        return state


@dataclass(eq=False)
class EdgeAnchor(ObjectAnchor):
    """Edge Anchor."""

    type: ObjectType = ObjectType.edge
    architype: Optional[EdgeArchitype] = None
    source: Optional[NodeAnchor] = None
    target: Optional[NodeAnchor] = None
    is_undirected: bool = False

    @classmethod
    def ref(cls, ref_id: str) -> Optional[EdgeAnchor]:
        """Return EdgeAnchor instance if existing."""
        if match := EDGE_ID_REGEX.search(ref_id):
            return cls(
                name=match.group(1),
                id=ObjectId(match.group(2)),
            )
        return None

    def _save(self) -> None:
        from jaclang.core.context import ExecutionContext

        jsrc = ExecutionContext.get().datasource

        if source := self.source:
            source.save()

        if target := self.target:
            target.save()

        jsrc.set(self)

    def save(self) -> None:
        """Save Anchor."""
        if self.architype:
            if not self.connected:
                self.connected = True
                self.hash = hash(dumps(self))
                self._save()
            elif self.current_access_level == 1 and self.hash != (
                _hash := hash(dumps(self))
            ):
                self.hash = _hash
                self._save()

    def destroy(self) -> None:
        """Delete Anchor."""
        if self.architype and self.current_access_level == 1:
            from jaclang.core.context import ExecutionContext

            jsrc = ExecutionContext.get().datasource

            source = self.source
            target = self.target
            self.detach()

            if source:
                source.save()
            if target:
                target.save()

            jsrc.remove(self)

    def sync(self, node: Optional["NodeAnchor"] = None) -> Optional[EdgeArchitype]:
        """Retrieve the Architype from db and return."""
        return cast(Optional[EdgeArchitype], super().sync(node))

    def unsync(self) -> EdgeAnchor:
        """Generate unlinked anchor."""
        return EdgeAnchor(name=self.name, id=self.id)

    def attach(
        self, src: NodeAnchor, trg: NodeAnchor, is_undirected: bool = False
    ) -> EdgeAnchor:
        """Attach edge to nodes."""
        self.source = src
        self.target = trg
        self.is_undirected = is_undirected
        src.edges.append(self)
        trg.edges.append(self)
        return self

    def detach(self) -> None:
        """Detach edge from nodes."""
        if source := self.source:
            source.edges.remove(self)
        if target := self.target:
            target.edges.remove(self)

        self.source = None
        self.target = None

    def spawn_call(self, walk: WalkerAnchor) -> WalkerArchitype:
        """Invoke data spatial call."""
        if target := self.target:
            return walk.spawn_call(target)
        else:
            raise ValueError("Edge has no target.")

    def __getstate__(self) -> dict[str, object]:
        """Override getstate for pickle and shelve."""
        state = super().__getstate__()
        if self.source:
            state["source"] = self.source.unsync()
        if self.target:
            state["target"] = self.target.unsync()
        return state


@dataclass(eq=False)
class WalkerAnchor(ObjectAnchor):
    """Walker Anchor."""

    type: ObjectType = ObjectType.walker
    architype: Optional[WalkerArchitype] = None
    path: list[Architype] = field(default_factory=list)
    next: list[Architype] = field(default_factory=list)
    ignores: list[Architype] = field(default_factory=list)
    disengaged: bool = False
    persistent: bool = False  # Disabled initially but can be adjusted

    @classmethod
    def ref(cls, ref_id: str) -> Optional[WalkerAnchor]:
        """Return EdgeAnchor instance if existing."""
        if ref_id and (match := WALKER_ID_REGEX.search(ref_id)):
            return cls(
                name=match.group(1),
                id=ObjectId(match.group(2)),
            )
        return None

    def _save(self) -> None:
        from jaclang.core.context import ExecutionContext

        ExecutionContext.get().datasource.set(self)

    def save(self) -> None:
        """Save Anchor."""
        if self.architype and self.current_access_level == 1:
            if not self.connected:
                self.connected = True
                self.hash = hash(dumps(self))
                self._save()
            elif self.hash != (_hash := hash(dumps(self))):
                self.hash = _hash
                self._save()

    def destroy(self) -> None:
        """Delete Anchor."""
        if self.architype and self.current_access_level == 1:
            from jaclang.core.context import ExecutionContext

            ExecutionContext.get().datasource.remove(self)

    def sync(self, node: Optional["NodeAnchor"] = None) -> Optional[WalkerArchitype]:
        """Retrieve the Architype from db and return."""
        return cast(Optional[WalkerArchitype], super().sync(node))

    def unsync(self) -> WalkerAnchor:
        """Generate unlinked anchor."""
        return WalkerAnchor(name=self.name, id=self.id)

    def visit_node(
        self,
        nds: (
            list[NodeArchitype | EdgeArchitype]
            | list[NodeArchitype]
            | list[EdgeArchitype]
            | NodeArchitype
            | EdgeArchitype
        ),
    ) -> bool:
        """Walker visits node."""
        nd_list: list[NodeArchitype | EdgeArchitype]
        if not isinstance(nds, list):
            nd_list = [nds]
        else:
            nd_list = list(nds)
        before_len = len(self.next)
        for i in nd_list:
            if i not in self.ignores:
                if isinstance(i, NodeArchitype):
                    self.next.append(i)
                elif isinstance(i, EdgeArchitype):
                    if (target := i._jac_.target) and (architype := target.architype):
                        self.next.append(architype)
                    else:
                        raise ValueError("Edge has no target.")
        return len(self.next) > before_len

    def ignore_node(
        self,
        nds: (
            list[NodeArchitype | EdgeArchitype]
            | list[NodeArchitype]
            | list[EdgeArchitype]
            | NodeArchitype
            | EdgeArchitype
        ),
    ) -> bool:
        """Walker ignores node."""
        nd_list: list[NodeArchitype | EdgeArchitype]
        if not isinstance(nds, list):
            nd_list = [nds]
        else:
            nd_list = list(nds)
        before_len = len(self.ignores)
        for i in nd_list:
            if i not in self.ignores:
                if isinstance(i, NodeArchitype):
                    self.ignores.append(i)
                elif isinstance(i, EdgeArchitype):
                    if (target := i._jac_.target) and (architype := target.architype):
                        self.ignores.append(architype)
                    else:
                        raise ValueError("Edge has no target.")
        return len(self.ignores) > before_len

    def disengage_now(self) -> None:
        """Disengage walker from traversal."""
        self.disengaged = True

    def spawn_call(self, nd: ObjectAnchor) -> WalkerArchitype:
        """Invoke data spatial call."""
        if (walker := self.sync()) and (node := nd.sync()):
            self.path = []
            self.next = [node]
            while len(self.next):
                node = self.next.pop(0)
                for i in node._jac_entry_funcs_:
                    if not i.trigger or isinstance(walker, i.trigger):
                        if i.func:
                            i.func(node, walker)
                        else:
                            raise ValueError(f"No function {i.name} to call.")
                    if self.disengaged:
                        return walker
                for i in walker._jac_entry_funcs_:
                    if not i.trigger or isinstance(node, i.trigger):
                        if i.func:
                            i.func(walker, node)
                        else:
                            raise ValueError(f"No function {i.name} to call.")
                    if self.disengaged:
                        return walker
                for i in walker._jac_exit_funcs_:
                    if not i.trigger or isinstance(node, i.trigger):
                        if i.func:
                            i.func(walker, node)
                        else:
                            raise ValueError(f"No function {i.name} to call.")
                    if self.disengaged:
                        return walker
                for i in node._jac_exit_funcs_:
                    if not i.trigger or isinstance(walker, i.trigger):
                        if i.func:
                            i.func(node, walker)
                        else:
                            raise ValueError(f"No function {i.name} to call.")
                    if self.disengaged:
                        return walker
            self.ignores = []
            return walker
        raise Exception(f"Invalid Reference {self.ref_id}")


class Architype(_Architype):
    """Architype Protocol."""

    def __init__(self) -> None:
        """Create default architype."""
        self._jac_: ObjectAnchor = ObjectAnchor(architype=self)
        self._jac_.allocate()

    def __getstate__(self) -> dict[str, object]:
        """Override getstate for pickle and shelve."""
        state = self.__dict__.copy()
        state["_jac_"] = None
        return state

    def __setstate__(self, state: dict) -> None:
        """Override setstate for pickle and shelve."""
        self.__dict__.update(state)

    def __eq__(self, other: object) -> bool:
        """Override equal implementation."""
        if isinstance(other, Architype):
            return super().__eq__(other)
        elif isinstance(other, ObjectAnchor):
            return self._jac_ == other

        return False

    def __hash__(self) -> int:
        """Override hash for architype."""
        return self._jac_.__hash__()

    def __repr__(self) -> str:
        """Override repr for architype."""
        return f"{self.__class__.__name__}"


class NodeArchitype(Architype):
    """Node Architype Protocol."""

    _jac_: NodeAnchor

    def __init__(self) -> None:
        """Create node architype."""
        self._jac_: NodeAnchor = NodeAnchor(
            name=self.__class__.__name__, architype=self
        )
        self._jac_.allocate()


class EdgeArchitype(Architype):
    """Edge Architype Protocol."""

    _jac_: EdgeAnchor

    def __init__(self) -> None:
        """Create edge architype."""
        self._jac_: EdgeAnchor = EdgeAnchor(
            name=self.__class__.__name__, architype=self
        )
        self._jac_.allocate()


class WalkerArchitype(Architype):
    """Walker Architype Protocol."""

    _jac_: WalkerAnchor

    def __init__(self) -> None:
        """Create walker architype."""
        self._jac_: WalkerAnchor = WalkerAnchor(
            name=self.__class__.__name__, architype=self
        )
        self._jac_.allocate()


class GenericEdge(EdgeArchitype):
    """Generic Root Node."""

    _jac_entry_funcs_ = []
    _jac_exit_funcs_ = []

    def __init__(self) -> None:
        """Create walker architype."""
        self._jac_: EdgeAnchor = EdgeAnchor(architype=self)
        self._jac_.allocate()


class Root(NodeArchitype):
    """Generic Root Node."""

    _jac_entry_funcs_ = []
    _jac_exit_funcs_ = []
    reachable_nodes: list[NodeArchitype] = []
    connections: set[tuple[NodeArchitype, NodeArchitype, EdgeArchitype]] = set()

    def __init__(self) -> None:
        """Create walker architype."""
        self._jac_: NodeAnchor = NodeAnchor(architype=self)
        self._jac_.allocate()

    def reset(self) -> None:
        """Reset the root."""
        self.reachable_nodes = []
        self.connections = set()
        self._jac_.edges = []
