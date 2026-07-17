"""
The 10 domain shards (§5.2). Each module exposes a `SHARD` factory that the PluginLoader
discovers automatically. Shards are the execution/ownership boundary; MITRE tactics are
cross-cutting tags, never a shard.
"""
