from types import NotImplementedType
from typing import Any, Literal, Self, Tuple as tTuple, Union as tUnion
from sympy.matrices.dense import MutableDenseMatrix
from sympy.polys.matrices.domainscalar import DomainScalar
from sympy.utilities.decorator import doctest_depends_on
from sympy.polys.domains import Domain
from sympy.polys.matrices.ddm import DDM
from sympy.polys.matrices.sdm import SDM

def DM(rows, domain) -> DomainMatrix:
    ...

class DomainMatrix:
    rep: tUnion[SDM, DDM]
    shape: tTuple[int, int]
    domain: Domain
    def __new__(cls, rows, shape, domain, *, fmt=...) -> Self:
        ...
    
    def __getnewargs__(self) -> tuple[list[Any] | dict[Any, Any], tTuple[int, int], Any]:
        ...
    
    def __getitem__(self, key) -> DomainScalar | Self:
        ...
    
    def getitem_sympy(self, i, j):
        ...
    
    def extract(self, rowslist, colslist) -> Self:
        ...
    
    def __setitem__(self, key, value) -> None:
        ...
    
    @classmethod
    def from_rep(cls, rep) -> Self:
        ...
    
    @classmethod
    def from_list(cls, rows, domain) -> DomainMatrix:
        ...
    
    @classmethod
    def from_list_sympy(cls, nrows, ncols, rows, **kwargs) -> DomainMatrix:
        ...
    
    @classmethod
    def from_dict_sympy(cls, nrows, ncols, elemsdict, **kwargs) -> DomainMatrix:
        ...
    
    @classmethod
    def from_Matrix(cls, M, fmt=..., **kwargs):
        ...
    
    @classmethod
    def get_domain(cls, items_sympy, **kwargs) -> tuple[Any, Any]:
        ...
    
    def copy(self) -> Self:
        ...
    
    def convert_to(self, K) -> Self:
        ...
    
    def to_sympy(self) -> Self:
        ...
    
    def to_field(self) -> Self:
        ...
    
    def to_sparse(self) -> Self:
        ...
    
    def to_dense(self) -> Self:
        ...
    
    def unify(self, *others, fmt=...) -> tuple[Any, ...]:
        ...
    
    def to_Matrix(self) -> MutableDenseMatrix:
        ...
    
    def to_list(self) -> list[Any]:
        ...
    
    def to_list_flat(self) -> list[Any]:
        ...
    
    def to_dok(self) -> dict[tuple[int, int], Any] | dict[tuple[Any, Any], Any]:
        ...
    
    def __repr__(self) -> str:
        ...
    
    def transpose(self) -> Self:
        ...
    
    def flat(self) -> list[Any]:
        ...
    
    @property
    def is_zero_matrix(self) -> bool:
        ...
    
    @property
    def is_upper(self) -> bool:
        ...
    
    @property
    def is_lower(self) -> bool:
        ...
    
    @property
    def is_square(self) -> bool:
        ...
    
    def rank(self) -> int:
        ...
    
    def hstack(A, *B) -> DomainMatrix:
        ...
    
    def vstack(A, *B) -> DomainMatrix:
        ...
    
    def applyfunc(self, func, domain=...) -> Self:
        ...
    
    def __add__(A, B) -> NotImplementedType:
        ...
    
    def __sub__(A, B) -> NotImplementedType:
        ...
    
    def __neg__(A) -> Self:
        ...
    
    def __mul__(A, B) -> DomainMatrix | Self | NotImplementedType:
        ...
    
    def __rmul__(A, B) -> DomainMatrix | Self | NotImplementedType:
        ...
    
    def __pow__(A, n) -> NotImplementedType | Self:
        ...
    
    def add(A, B) -> Self:
        ...
    
    def sub(A, B) -> Self:
        ...
    
    def neg(A) -> Self:
        ...
    
    def mul(A, b) -> Self:
        ...
    
    def rmul(A, b) -> Self:
        ...
    
    def matmul(A, B) -> Self:
        ...
    
    def scalarmul(A, lamda) -> DomainMatrix | Self:
        ...
    
    def rscalarmul(A, lamda) -> DomainMatrix | Self:
        ...
    
    def mul_elementwise(A, B) -> Self:
        ...
    
    def __truediv__(A, lamda) -> NotImplementedType:
        ...
    
    def pow(A, n) -> Self:
        ...
    
    def scc(self) -> list[Any]:
        ...
    
    def rref(self) -> tuple[Self, tuple[Any, ...]]:
        ...
    
    def columnspace(self) -> Self:
        ...
    
    def rowspace(self) -> Self:
        ...
    
    def nullspace(self) -> Self:
        ...
    
    def inv(self) -> Self:
        ...
    
    def det(self):
        ...
    
    def lu(self) -> tuple[Self, Self, list[Any]]:
        ...
    
    def lu_solve(self, rhs) -> Self:
        ...
    
    def charpoly(self) -> list[Any]:
        ...
    
    @classmethod
    def eye(cls, shape, domain) -> Self:
        ...
    
    @classmethod
    def diag(cls, diagonal, domain, shape=...) -> Self:
        ...
    
    @classmethod
    def zeros(cls, shape, domain, *, fmt=...) -> Self:
        ...
    
    @classmethod
    def ones(cls, shape, domain) -> Self:
        ...
    
    def __eq__(A, B) -> bool:
        ...
    
    def unify_eq(A, B) -> Literal[False]:
        ...
    
    def lll(A, delta=...) -> DomainMatrix:
        ...
    
    def lll_transform(A, delta=...) -> tuple[DomainMatrix, DomainMatrix]:
        ...
    


