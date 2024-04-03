from typing import Mapping
from numpy.typing import ArrayLike

from collections import deque
from heapq import heappop, heappush
from itertools import count

from ...classes.graph import Graph

__all__ = [
    "dijkstra_path",
    "dijkstra_path_length",
    "bidirectional_dijkstra",
    "single_source_dijkstra",
    "single_source_dijkstra_path",
    "single_source_dijkstra_path_length",
    "multi_source_dijkstra",
    "multi_source_dijkstra_path",
    "multi_source_dijkstra_path_length",
    "all_pairs_dijkstra",
    "all_pairs_dijkstra_path",
    "all_pairs_dijkstra_path_length",
    "dijkstra_predecessor_and_distance",
    "bellman_ford_path",
    "bellman_ford_path_length",
    "single_source_bellman_ford",
    "single_source_bellman_ford_path",
    "single_source_bellman_ford_path_length",
    "all_pairs_bellman_ford_path",
    "all_pairs_bellman_ford_path_length",
    "bellman_ford_predecessor_and_distance",
    "negative_edge_cycle",
    "find_negative_cycle",
    "goldberg_radzik",
    "johnson",
]

def dijkstra_path(G: Graph, source, target, weight="weight") -> ArrayLike: ...
def dijkstra_path_length(G: Graph, source, target, weight="weight"): ...
def single_source_dijkstra_path(
    G: Graph, source, cutoff=None, weight="weight"
) -> Mapping: ...
def single_source_dijkstra_path_length(
    G: Graph, source, cutoff=None, weight="weight"
) -> Mapping: ...
def single_source_dijkstra(
    G: Graph, source, target=None, cutoff=None, weight="weight"
): ...
def multi_source_dijkstra_path(
    G: Graph, sources, cutoff=None, weight="weight"
) -> Mapping: ...
def multi_source_dijkstra_path_length(
    G: Graph, sources, cutoff=None, weight="weight"
) -> Mapping: ...
def multi_source_dijkstra(
    G: Graph, sources, target=None, cutoff=None, weight="weight"
): ...
def dijkstra_predecessor_and_distance(
    G: Graph, source, cutoff=None, weight="weight"
) -> dict: ...
def all_pairs_dijkstra(G: Graph, cutoff=None, weight="weight"): ...
def all_pairs_dijkstra_path_length(G: Graph, cutoff=None, weight="weight"): ...
def all_pairs_dijkstra_path(G: Graph, cutoff=None, weight="weight") -> Mapping: ...
def bellman_ford_predecessor_and_distance(
    G: Graph, source, target=None, weight="weight", heuristic: bool = False
) -> dict: ...
def bellman_ford_path(G: Graph, source, target, weight="weight") -> ArrayLike: ...
def bellman_ford_path_length(G: Graph, source, target, weight="weight"): ...
def single_source_bellman_ford_path(G: Graph, source, weight="weight") -> Mapping: ...
def single_source_bellman_ford_path_length(G: Graph, source, weight="weight"): ...
def single_source_bellman_ford(G: Graph, source, target=None, weight="weight"): ...
def all_pairs_bellman_ford_path_length(G: Graph, weight="weight"): ...
def all_pairs_bellman_ford_path(G: Graph, weight="weight") -> Mapping: ...
def goldberg_radzik(G: Graph, source, weight="weight") -> dict: ...
def negative_edge_cycle(G: Graph, weight="weight", heuristic: bool = True) -> bool: ...
def find_negative_cycle(G: Graph, source, weight="weight") -> ArrayLike: ...
def bidirectional_dijkstra(G: Graph, source, target, weight="weight"): ...
def johnson(G: Graph, weight="weight") -> Mapping: ...
