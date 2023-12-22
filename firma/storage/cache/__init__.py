# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import random

import redis

class CacheRedis(object):
    name = "redis"
    CacheException = redis.ConnectionError

    OLD_TTL = 30 * 60           # Half an hour


    def __init__(self, namespace, get_current_version_state, **kwargs):
        self._logger = kwargs.pop("logger", None)
        self._namespace = namespace
        if "port" in kwargs and kwargs["port"] is None:
            del kwargs["port"]

        self._cache = redis.StrictRedis(**kwargs)
        self._online = False            # `False` if last connection failed
        self._old_ttl = self.OLD_TTL
        self._get_current_version_state = get_current_version_state

        (version, state) = self._get_current_version_state()
        try:
            self.set_version(version)
            self.set_state(state)
        except self.CacheException:
            pass


    def __len__(self):
        return len(list(self._keys_iter("*")))


    def log(self, message):
        if not self._logger:
            return
        self._logger.info(message)


    def online(self):
        try:
            self._cache.ping()
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
            return False
        else:
            return True


    def status(self):
        status = "offline"
        state = ""
        try:
            status = len(self)
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
        else:
            state = "%s : " % self._get_state()
        return "%s : %s : %s%s" % (self.name, self._namespace, state, status)


    def check(self):
        if not self._online:
            try:
                self._cache.ping()
            except (redis.ConnectionError, redis.exceptions.ResponseError):
                return
            else:
                self.log("Cache has come online")
                self._online = True

        # In case cache has been flushed:
        if not (self._get_version() and self._get_state()):
            (version, state) = self._get_current_version_state()
            self.set_version(version)
            self.set_state(state)


    def _fail(self):
        if self._online:
            self.log("Cache has gone offline")
        self._online = False



    def _get_version(self):
        return self._get("version")


    def _get_state(self):
        return self._get("state")


    @property
    def _version_prefix(self):
        return "%s:" % (self._get_version())


    @property
    def _version_state_prefix(self):
        return "%s:%s:" % (self._get_version(), self._get_state())


    def _prefix(self, key, expired=False):
        if expired:
            return "%s-:%s" % (self._version_prefix, key)
        return "%s%s" % (self._version_state_prefix, key)


    def _prefix_previous(self, key):
        return "%s*:%s" % (self._version_prefix, key)


    @staticmethod
    def _unprefix(key):
        """It's important that this doesn't hit the cache
        because it may be called many times by `iter_item`."""
        return key.split(":", 2)[2]


    def _expire_old(self):
        """
        Expire records from old states.
        Delete records from old versions.
        """
        expired = 0
        deleted = 0
        version_state_prefix = self._version_state_prefix
        version_prefix = self._version_prefix
        for key in self._keys_iter("*"):
            if key in ("state", "version"):
                continue
            if key.startswith(version_state_prefix):
                continue
            if key.startswith(version_prefix):
                if self._old_ttl < self._ttl(key):
                    random_ttl = int(random.random() * self._old_ttl)
                    self.log("Cache: Expire %s in %ds." % (key, random_ttl))
                    self._expire(key, random_ttl)
                    expired += 1
            else:
                self.log("Cache: Delete %s." % (key))
                self._delete(key)
                deleted += 1
        self.log("Cache: Deleted %d old version records and expiring %d old "
                 "state records at random over the next %ss." % (
                     deleted, expired, self._old_ttl))


    def set_version(self, version):
        if not version:
            return
        if version == self._get_version():
            self.log("Cache: set version equal (%s)" % version)
            return
        self._set("version", version)
        try:
            self._expire_old()
        except self.CacheException:
            pass


    def set_state(self, state):
        if not state:
            return
        if state == self._get_state():
            self.log("Cache: set state equal (%s)" % state)
            return
        self._set("state", state)
        try:
            self._expire_old()
        except self.CacheException:
            pass



    def _key(self, key):
        return self._namespace + ":" + key


    def _unkey(self, key):
        return key[len(self._namespace + ":"):]



    def _exists(self, key):
        try:
            return self._cache.exists(self._key(key))
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
        return None


    def _get(self, key):
        try:
            value = self._cache.get(self._key(key))
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
            return None

        value = value and value.decode()

        if key not in ("state", "version"):
            if value is None:
                self.log("Cache: miss %s" % key)
            else:
                self.log("Cache: hit  %s" % key)
        return value


    def _set(self, key, value, ttl=None):
        "Returns `True` on failure."
        try:
            self._cache.set(self._key(key), value)
            if ttl is not None:
                self._cache.expire(self._key(key), ttl)
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
            return True
        self.log("Cache: set  %s" % key)
        return False


    def _delete(self, key):
        "Returns `True` on failure."
        try:
            self._cache.delete(self._key(key))
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
            return True
        return False


    def _expire(self, key, ttl):
        "Returns `True` on failure."
        try:
            self._cache.expire(self._key(key), ttl)
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
            return True
        return False


    def _ttl(self, key):
        "Returns `0` on failure."
        try:
            return self._cache.ttl(self._key(key))
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
            return 0


    def _keys_iter(self, pattern):
        """
        Return keys without namespace.
        Must wrap caller in `try` statement to catch `CacheException`.
        """
        try:
            for key in self._cache.keys(self._key(pattern)):
                key = key.decode()
                yield self._unkey(key)
        except (redis.ConnectionError, redis.exceptions.ResponseError):
            self._fail()
            raise self.CacheException()


    # App access functions


    def set_item(self, key, value, ttl=False, expired=False):
        """
        We could delete old versions here, but for now
        we'll leave them to expire since they'll have `OLD_TTL`.
        """
        self.check()
        return self._set(
            self._prefix(key, expired=expired),
            value, ttl=ttl)


    def get_item(self, key, accept_old=False):
        """
        If `accept_old` is a set, add old TTL to it.
        """
        current_key = self._prefix(key)
        value = self._get(current_key)
        if value or accept_old is False:
            return value
        previous_pattern = self._prefix_previous(key)
        try:
            for match_key in self._keys_iter(previous_pattern):
                value = self._get(match_key)
                if isinstance(accept_old, set):
                    ttl = self._ttl(match_key)
                    accept_old.add(ttl)
                return value
        except self.CacheException:
            pass
        return None


    def delete_item(self, key):
        return self._delete(self._prefix(key))


    def exists_item(self, key, accept_old=False):
        current_key = self._prefix(key)
        value = self._exists(current_key)
        if value or not accept_old:
            return value
        previous_pattern = self._prefix_previous(key)
        for match_key in self._keys_iter(previous_pattern):
            value = self._exists(match_key)
            if value:
                return value
        return None


    def iter_item(self, pattern):
        pattern = self._prefix(pattern)
        for key in self._keys_iter(pattern):
            yield self._unprefix(key)
