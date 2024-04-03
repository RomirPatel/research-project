from typing import Any, Callable, Generator, Literal, NoReturn, Self
from sympy.core.basic import Basic
from sympy.core.symbol import Symbol
from sympy.polys.domains.gaussiandomains import GaussianIntegerRing, GaussianRationalField
from sympy.polys.orderings import LexOrder
from sympy.utilities import public

__all__ = ["Options"]
class Option:
    option: str | None = ...
    is_Flag = ...
    requires: list[str] = ...
    excludes: list[str] = ...
    after: list[str] = ...
    before: list[str] = ...
    @classmethod
    def default(cls) -> None:
        ...
    
    @classmethod
    def preprocess(cls, option) -> None:
        ...
    
    @classmethod
    def postprocess(cls, options) -> None:
        ...
    


class Flag(Option):
    is_Flag = ...


class BooleanOption(Option):
    @classmethod
    def preprocess(cls, value) -> bool:
        ...
    


class OptionType(type):
    def __init__(cls, *args, **kwargs) -> None:
        ...
    


@public
class Options(dict):
    __order__ = ...
    __options__: dict[str, type[Option]] = ...
    def __init__(self, gens, args, flags=..., strict=...) -> None:
        ...
    
    def clone(self, updates=...) -> Self:
        ...
    
    def __setattr__(self, attr, value) -> None:
        ...
    
    @property
    def args(self) -> dict[Any, Any]:
        ...
    
    @property
    def options(self) -> dict[Any, Any]:
        ...
    
    @property
    def flags(self) -> dict[Any, Any]:
        ...
    


class Expand(BooleanOption, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes: list[str] = ...
    @classmethod
    def default(cls) -> Literal[True]:
        ...
    


class Gens(Option, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes: list[str] = ...
    @classmethod
    def default(cls) -> tuple[()]:
        ...
    
    @classmethod
    def preprocess(cls, gens) -> tuple[Basic, ...]:
        ...
    


class Wrt(Option, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes: list[str] = ...
    _re_split = ...
    @classmethod
    def preprocess(cls, wrt) -> list[str] | list[Any] | list[str | Any]:
        ...
    


class Sort(Option, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes: list[str] = ...
    @classmethod
    def default(cls) -> list[Any]:
        ...
    
    @classmethod
    def preprocess(cls, sort) -> list[str]:
        ...
    


class Order(Option, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes: list[str] = ...
    @classmethod
    def default(cls) -> LexOrder:
        ...
    
    @classmethod
    def preprocess(cls, order) -> Callable[..., Any] | LexOrder:
        ...
    


class Field(BooleanOption, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes = ...


class Greedy(BooleanOption, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes = ...


class Composite(BooleanOption, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> None:
        ...
    
    requires: list[str] = ...
    excludes = ...


class Domain(Option, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes = ...
    after = ...
    _re_realfield = ...
    _re_complexfield = ...
    _re_finitefield = ...
    _re_polynomial = ...
    _re_fraction = ...
    _re_algebraic = ...
    @classmethod
    def preprocess(cls, domain) -> Any | GaussianIntegerRing | GaussianRationalField:
        ...
    
    @classmethod
    def postprocess(cls, options) -> None:
        ...
    


class Split(BooleanOption, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes = ...
    @classmethod
    def postprocess(cls, options) -> None:
        ...
    


class Gaussian(BooleanOption, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes = ...
    @classmethod
    def postprocess(cls, options) -> None:
        ...
    


class Extension(Option, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes = ...
    @classmethod
    def preprocess(cls, extension) -> bool | set[Any] | None:
        ...
    
    @classmethod
    def postprocess(cls, options) -> None:
        ...
    


class Modulus(Option, metaclass=OptionType):
    option = ...
    requires: list[str] = ...
    excludes = ...
    @classmethod
    def preprocess(cls, modulus) -> int:
        ...
    
    @classmethod
    def postprocess(cls, options) -> None:
        ...
    


class Symmetric(BooleanOption, metaclass=OptionType):
    option = ...
    requires = ...
    excludes = ...


class Strict(BooleanOption, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> Literal[True]:
        ...
    


class Auto(BooleanOption, Flag, metaclass=OptionType):
    option = ...
    after = ...
    @classmethod
    def default(cls) -> Literal[True]:
        ...
    
    @classmethod
    def postprocess(cls, options) -> None:
        ...
    


class Frac(BooleanOption, Flag, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> Literal[False]:
        ...
    


class Formal(BooleanOption, Flag, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> Literal[False]:
        ...
    


class Polys(BooleanOption, Flag, metaclass=OptionType):
    option = ...


class Include(BooleanOption, Flag, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> Literal[False]:
        ...
    


class All(BooleanOption, Flag, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> Literal[False]:
        ...
    


class Gen(Flag, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> Literal[0]:
        ...
    
    @classmethod
    def preprocess(cls, gen) -> Basic | int:
        ...
    


class Series(BooleanOption, Flag, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> Literal[False]:
        ...
    


class Symbols(Flag, metaclass=OptionType):
    option = ...
    @classmethod
    def default(cls) -> Generator[Symbol | Any, Any, NoReturn]:
        ...
    
    @classmethod
    def preprocess(cls, symbols):
        ...
    


class Method(Flag, metaclass=OptionType):
    option = ...
    @classmethod
    def preprocess(cls, method) -> str:
        ...
    


def build_options(gens, args=...) -> Any:
    ...

def allowed_flags(args, flags) -> None:
    ...

def set_defaults(options, **defaults) -> dict[Any, Any]:
    ...

