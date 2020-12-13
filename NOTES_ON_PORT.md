# Notes on porting to zbus

Plan: start a section of code that will be easy convert to zbus, while keeping dbus dependency. I think that this would be `Item`, which is a "leaf" struct (meaning it doesn't create other dbus-connected structs). This way I only have to worry about any data being received, and not so much data being returned.

Plan, revised: I should still start with Item. However, the place where I'll slide zbus in is a little different then I had thought. This is because my code currently is structured:
- With an `Interface` (which should actually be called a `proxy` that talks to the interface) that is a very low-level implementation of basics like method calls.
- And then all the details of talking to the service interface are handled directly in `Item`'s methods.

With zbus, I would instead have:
- A derived `dbus_proxy`, which would set up all the boilerplate for talking to a an interface, and then
- Methods in `Item` would generally just be calling the derived `dbus_proxy`.
- This means that with zbus, I should be able to get rid of `Interface`.

So, my first step should be to replace usage of the `Item` proxy.
