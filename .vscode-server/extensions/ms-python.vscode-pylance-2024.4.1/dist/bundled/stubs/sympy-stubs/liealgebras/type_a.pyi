from typing import Any, Self
from sympy.liealgebras.cartan_type import Standard_Cartan

class TypeA(Standard_Cartan):
    def __new__(cls, n) -> Self:
        ...
    
    def dimension(self):
        ...
    
    def basic_root(self, i, j):
        ...
    
    def simple_root(self, i):
        ...
    
    def positive_roots(self) -> dict[Any, Any]:
        ...
    
    def highest_root(self):
        ...
    
    def roots(self):
        ...
    
    def cartan_matrix(self):
        ...
    
    def basis(self):
        ...
    
    def lie_algebra(self) -> str:
        ...
    
    def dynkin_diagram(self) -> str:
        ...
    


