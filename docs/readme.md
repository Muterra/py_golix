# Gotchas and security notes

As a FirstParty, it is **critical** to run receive_<object> on **all** objects before use. The astute will note that for several network objects, ex. static bindings, unpack() presents sufficient information to use the bindings. It does not, however, verify the authenticity of the object, leaving it thoroughly vulnerable to spoofing.