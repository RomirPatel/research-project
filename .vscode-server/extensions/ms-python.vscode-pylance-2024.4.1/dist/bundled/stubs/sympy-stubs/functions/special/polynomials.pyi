from typing import Any
from sympy.concrete.summations import Sum
from sympy.core.function import Function, UndefinedFunction
from sympy.core.mul import Mul
from sympy.core.relational import Equality, Ne, Relational

_x = ...
class OrthogonalPolynomial(Function):
    ...


class jacobi(OrthogonalPolynomial):
    @classmethod
    def eval(cls, n, a, b, x) -> type[UndefinedFunction] | Any | None:
        ...
    
    def fdiff(self, argindex=...) -> Equality | Relational | Ne | Sum:
        ...
    


def jacobi_normalized(n, a, b, x):
    ...

class gegenbauer(OrthogonalPolynomial):
    @classmethod
    def eval(cls, n, a, x) -> type[UndefinedFunction] | None:
        ...
    
    def fdiff(self, argindex=...) -> Equality | Relational | Ne | Sum:
        ...
    


class chebyshevt(OrthogonalPolynomial):
    _ortho_poly = ...
    @classmethod
    def eval(cls, n, x) -> type[UndefinedFunction] | None:
        ...
    
    def fdiff(self, argindex=...):
        ...
    


class chebyshevu(OrthogonalPolynomial):
    _ortho_poly = ...
    @classmethod
    def eval(cls, n, x) -> type[UndefinedFunction] | None:
        ...
    
    def fdiff(self, argindex=...):
        ...
    


class chebyshevt_root(Function):
    @classmethod
    def eval(cls, n, k) -> type[UndefinedFunction]:
        ...
    


class chebyshevu_root(Function):
    @classmethod
    def eval(cls, n, k) -> type[UndefinedFunction]:
        ...
    


class legendre(OrthogonalPolynomial):
    _ortho_poly = ...
    @classmethod
    def eval(cls, n, x) -> type[UndefinedFunction] | None:
        ...
    
    def fdiff(self, argindex=...):
        ...
    


class assoc_legendre(Function):
    @classmethod
    def eval(cls, n, m, x) -> type[UndefinedFunction] | None:
        ...
    
    def fdiff(self, argindex=...):
        ...
    


class hermite(OrthogonalPolynomial):
    _ortho_poly = ...
    @classmethod
    def eval(cls, n, x) -> None:
        ...
    
    def fdiff(self, argindex=...):
        ...
    


class hermite_prob(OrthogonalPolynomial):
    _ortho_poly = ...
    @classmethod
    def eval(cls, n, x) -> None:
        ...
    
    def fdiff(self, argindex=...):
        ...
    


class laguerre(OrthogonalPolynomial):
    _ortho_poly = ...
    @classmethod
    def eval(cls, n, x) -> None:
        ...
    
    def fdiff(self, argindex=...) -> Mul:
        ...
    


class assoc_laguerre(OrthogonalPolynomial):
    @classmethod
    def eval(cls, n, alpha, x) -> type[UndefinedFunction] | Any | None:
        ...
    
    def fdiff(self, argindex=...) -> Equality | Relational | Ne | Sum | Mul:
        ...
    


