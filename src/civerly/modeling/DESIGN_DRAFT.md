# On Model Options

- How many options are required once we implement the separate encoders?
  - Balance between the number of functions vs. dead-weight parameters / non-homogenity
    in function definitions because of parameter variety?

# Implementing encoders

## Simple encoding registry


```py
class EncodingsRegistry(MapLike):
    ...

encodings: EncodingsRegistry

encoding = encodings[type(component)]
model = encoding(component, model_options)

```

## Singledispatch

```py
from functools import singledispatch

@singledispatch
def encode(arg, verbose=False):
    if verbose:
        print("Let me just say,", end=" ")
    print(arg)


def nothing(arg, verbose=True):
    return

encode.register(type(None), nothing)
```

Then the user will provide the encoding functions which depend on SAT/MILP/whatever.

`singledispatch` is good because there is an automatic error message if the user 
implements a function with a wrong number of e.g. required positional arguments:

```py
from functools import singledispatch

@singledispatch
def fun(arg, verbose=True):
    print(arg)


def something_else():
    print()

fun.register(int, something_else)
fun()
---------------------------------
TypeError          
     12     print()
     14 fun.register(int, something_else)
---> 15 fun()

...<more traceback>...
    904 def wrapper(*args, **kw):
    905     if not args:
--> 906         raise TypeError(f'{funcname} requires at least 1 positional argument')
    907     return dispatch(args[0].__class__)(*args, **kw)

TypeError: fun requires at least 1 positional argument
```

# Specifying encoding functions

## The user provides a function when a component is initialised

The user should provide a function which then will be registered **by a component**.

We then call `Component.model(model_options)` to get the model.

Aligns with the current workflow of CiVerLy.


## The user provides a function to some `Component`-external `Modeler`-type class

Conceptually:
```py

class Modeler(...):
    def __init__(self, ...user provided encoding functions):
        self.registry = CIVERLY_DEFAULT if user gave None else user specified stuff

    def model(self, component, model_options):
        get encoder from register the modeler keeps
        encode
        return model
```

## `MODEL_OPTIONS`

- Instead of specifying encoding functions separately, we handle it through model options

## Tentative Combo

- The easiest way: `Component.model` calls `singledispatch.encode(component: Component, ctx: EncodingContext)`; 
  previously at `__init__` time the user provided a 
  `user_encodings: dict[Component, Callable[Component, EncodingContext]]` 
  and we use `encode.register(comp, func) for comp, func in user_encodings.items()`
  to register the functions; 
  Then, we do not need to keep track of any dicts, since this is done for us through `singledispatch`.


# Drafts

## Parity Polytope

```py
def _parity_violating_assignments_old(n: int, rhs: int):
    return (assignment for assignment in product((0, 1), repeat=n) if sum(assignment) % 2 != rhs)

#
# @Inbook{Lancia2018,
# author="Lancia, Giuseppe
# and Serafini, Paolo",
# title="The Parity Polytope",
# bookTitle="Compact Extended Linear Programming Models",
# year="2018",
# publisher="Springer International Publishing",
# address="Cham",
# pages="113--121",
# abstract="This chapter is focused on the parity polytope, i.e., the convex hull of all 0-1 vectors with an even number of ones.",
# isbn="978-3-319-63976-5",
# doi="10.1007/978-3-319-63976-5_8",
# url="https://doi.org/10.1007/978-3-319-63976-5_8"
# }
#


def _even_parity_polytope_h_form(ctx: MILPContext, matrix, IN, OUT):
    """
    Let F be a subset of {0, 1, ..., n - 1} and let |F| = 1 mod 2.

    External representation:
        sum_{i in F} zi - sum_{i not in F} zi <= |F| - 1

    Re-aranging variables:
        sum_{i in F} (1 - zi) - sum_{i not in F} zi >= 1


    """

    equations = _linear_layer_equations(matrix, IN, OUT)
    for equation in equations:
        for assignment in _parity_violating_assignments(len(equation.variables), rhs=0):
            ctx.model.add_constraint(
                sum(
                    1 - var if value else var
                    for var, value in zip(equation.variables, assignment, strict=True)
                )
                >= 1
            )
```

