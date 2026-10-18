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

