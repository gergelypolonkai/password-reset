# -*- coding: utf8
# Copyright (C) 2016, Gergely Polonkai
# Licensed under GNU GPL 3+

import getpass
from gi.repository import GnomeKeyring
from xdg import BaseDirectory
import gnupg
import os
import collections


class OrderedSet(collections.MutableSet):
    def __init__(self, iterable=None):
        self.end = end = []
        end += [None, end, end]         # sentinel node for doubly linked list
        self.map = {}                   # key --> [key, prev, next]
        if iterable is not None:
            self |= iterable

    def __len__(self):
        return len(self.map)

    def __contains__(self, key):
        return key in self.map

    def add(self, key):
        if key not in self.map:
            end = self.end
            curr = end[1]
            curr[2] = end[1] = self.map[key] = [key, curr, end]

    def discard(self, key):
        if key in self.map:
            key, prev, next = self.map.pop(key)
            prev[2] = next
            next[1] = prev

    def __iter__(self):
        end = self.end
        curr = end[2]
        while curr is not end:
            yield curr[0]
            curr = curr[2]

    def __reversed__(self):
        end = self.end
        curr = end[1]
        while curr is not end:
            yield curr[0]
            curr = curr[1]

    def pop(self, last=True):
        if not self:
            raise KeyError('set is empty')
        key = self.end[1][0] if last else self.end[2][0]
        self.discard(key)
        return key

    def __repr__(self):
        if not self:
            return '%s()' % (self.__class__.__name__,)
        return '%s(%r)' % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        return set(self) == set(other)


def check_password(info, old_passwords, new_password=None):
    for idx, password in enumerate(old_passwords):
        if password == new_password:
            continue

        if info.get_secret() == password:
            print("Found matching password for record {}: {}".format(
                idx, info.get_display_name()))

            if new_password is not None:
                info.set_secret(new_password)

                return True

    return False


def main(args):
    cache_file = os.path.join(BaseDirectory.save_cache_path('password_reset'),
                              'old-passwords.gpg')
    old_password = getpass.getpass("Enter the password we are looking for: ")
    new_password = getpass.getpass("Enter the new password: ")

    passwords = OrderedSet()
    gpg = gnupg.GPG()

    # Read cache file contents
    if os.path.isfile(cache_file):
        with open(cache_file) as f:
            contents = gpg.decrypt(f.read())

        for password in str(contents).split('\n'):
            passwords.add(password)

    if old_password != '':
        passwords.add(old_password)

    if new_password != '':
        passwords.add(new_password)
    else:
        new_password = None

    password_file = '\n'.join(passwords)

    # Write the cache file
    encrypted_password_file = gpg.encrypt('\n'.join(passwords), 'D9D2E96E')

    with open(cache_file, 'w') as f:
        f.write(str(encrypted_password_file))

    # Fetch all the keyrings
    result, keyrings = GnomeKeyring.list_keyring_names_sync()
    if result != GnomeKeyring.Result.OK:
        print("Failed to fetch keyrings")

        return 1

    update_count = 0

    for keyring in keyrings:
        result, items = GnomeKeyring.list_item_ids_sync(keyring)

        # Read contents of the keyring
        if result != GnomeKeyring.Result.OK:
            print("Failed to fetch keyring items from {}".format(keyring))

            continue

        # Iterate over all keys
        for itemid in items:
            result, info = GnomeKeyring.item_get_info_full_sync(
                keyring,
                itemid,
                GnomeKeyring.ItemInfoFlags.SECRET)

            if result != GnomeKeyring.Result.OK:
                print("Failed to get item {} from keyring {}".format(
                    itemid,
                    keyring))

                continue

            if check_password(info, passwords, new_password=new_password):
                result = GnomeKeyring.item_set_info_sync(keyring, itemid, info)

                if result != GnomeKeyring.Result.OK:
                    print("Failed to save item {} in keyring {}".format(
                        info.get_display_name(), keyring))
                else:
                    update_count += 1

    print("Updated {} keys".format(update_count))
