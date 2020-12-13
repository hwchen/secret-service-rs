# Notes on porting to zbus

Plan: start a section of code that will be easy convert to zbus, while keeping dbus dependency. I think that this would be `Item`, which is a "leaf" struct (meaning it doesn't create other dbus-connected structs). This way I only have to worry about any data being received, and not so much data being returned.

