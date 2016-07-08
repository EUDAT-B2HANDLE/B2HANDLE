.. _givingpermissiontousers:

=================================
Giving write permissions to users
=================================

No matter which of the methods for *authentication* is used, in both cases the
Handle Server admin (or prefix owner) has to give write permissions to
the user (*authorisation*):

* Authentication: Are you who you claim to be?
* Authorisation: Are you allowed to do what you are trying to do?

These are several ways to grant write permissions to users **300:foo/bar**
and **301:foo/bar** and **300:foo/doe**:

1. :ref:`method1`.
2. :ref:`method2`.
3. :ref:`method3`.

Please note that while the third method looks most complex, it may be
the easiest one, as it is most easily modified and extended (without
having to contact the prefix provider to make changes in the **0.NA/foo** record).

.. _method1:

HS_ADMIN entry for each username in the prefix owner handle record
==================================================================

We can give users write permissions by creating a ``HS_ADMIN`` entry
for each username in the prefix owner handle record (i.e. somewhere
in the record **0.NA/foo**).


    **Handle record 0.NA/foo:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    100   HS_ADMIN  (refers to 300:foo/bar)
    101   HS_ADMIN  (refers to 301:foo/bar)
    102   HS_ADMIN  (refers to 300:foo/doe)
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/bar:**

    ===== ========= ==========
    Index Key       Value
     ...  ...       ...
    300   HS_SECKEY *mypassword*
    301   HS_PUBKEY 0000A552100
     ...  ...       ...
    ===== ========= ==========

    **Handle record foo/doe:**

    ===== ========= ==========
    Index Key       Value
     ...  ...       ...
    300   HS_SECKEY *mypassword*
     ...  ...       ...
    ===== ========= ==========



.. _method2:

HS_VLIST entry containing usernames in the prefix owner handle record
=====================================================================

We can grant users write permissions by adding the usernames (**300:foo/bar**,
**301:foo/bar** and **300:foo/doe**) to a ``HS_VLIST`` entry in the
prefix owner handle record (i.e. somewhere in the record **0.NA/foo**),
which was referenced in a ``HS_ADMIN`` entry in **0.NA/foo**.

    **Handle record 0.NA/foo:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    100   HS_ADMIN  (refers to 200:0.NA/foo)
    200   HS_VLIST  300:foo/bar
                    301:foo/bar
                    300:foo/doe
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/bar:**

    ===== ========= ==========
    Index Key       Value
     ...  ...       ...
    300   HS_SECKEY *mypassword*
    301   HS_PUBKEY 0000A552100
     ...  ...       ...
    ===== ========= ==========

    **Handle record foo/doe:**

    ===== ========= ==========
    Index Key       Value
     ...  ...       ...
    300   HS_SECKEY *mypassword*
     ...  ...       ...
    ===== ========= ==========


.. _method3:

HS_VLIST entry containing usernames in another place
====================================================

We can give users write permissions by adding the usernames (**300:foo/bar**, **301:foo/bar**
and **300:foo/doe**) to any ``HS_VLIST`` entry referenced somewhere in **0.NA/foo**.


The difference to the previous method is: This ``HS_VLIST`` does not have to be inside
the **0.NA/foo** record, it only has to be referenced there - it can be put into
a different handle, e.g. **foo/admin**, so changes to the ``HS_VLIST`` can be made
without having to ask the prefix provider (who is usually the only one able to change
entries in **0.NA/foo**).

For example, if there is a ``HS_ADMIN`` at index 101 of **0.NA/foo** which points to
a ``HS_VLIST`` at the index 200 in **0.NA/foo**, which points to a ``HS_VLIST`` at
index 200 in 'foo/admin', which points to a ``HS_SECKEY`` at index 300 in 'foo/bar' -
then **300:foo/bar** is a username with all the permissions stated in the ``HS_ADMIN``
entry at the index 101 of **0.NA/foo**.


    **Handle record 0.NA/foo:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    100   HS_ADMIN  (refers to 200:0.NA/foo)
    200   HS_VLIST  200:foo/admin
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/admin:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    200   HS_VLIST  300:foo/bar
                    301:foo/bar
                    300:foo/doe
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/bar:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    300   HS_SECKEY *mypassword*
    301   HS_PUBKEY 0000A552100
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/doe:**

    ===== ========= =======================
    Index Key       Value
     ...  ...       ...
    300   HS_SECKEY *mypassword*
     ...  ...       ...
    ===== ========= =======================

    .. important:: This setting gives write permissions to users foo/bar and foo/doe.
      You should also make sure that those users are not able to change other people's
      write permissions. For this, make sure the ``HS_ADMIN`` entries of the handles concerned
      with user administration point to a username or ``HS_VLIST`` that only you can
      access.

To ensure that only you (or your admin colleagues) can change users' write permissions,
we add a list of admins (another ``HS_VLIST``) to the admin handle record (foo/admin)
and reference it in the ``HS_ADMIN`` entry of the admin handle record. Only the users
in this list can administer users. We also have to add that new ``HS_VLIST`` to the 
``HS_VLIST`` in 200:0.NA/foo, to make sure it has write permissions.

    **Handle record 0.NA/foo:**

    ===== ========= =======================
    Index Key       Value
    ...   ...       ...
    100   HS_ADMIN  (refers to 200:0.NA/foo)
    200   HS_VLIST  200:foo/admin
                    201:foo/admin
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/admin:**

    ===== ========= =======================
    Index Key       Value
    ...   ...       ...
    100   HS_ADMIN  (refers to 201:foo/admin)
    200   HS_VLIST  300:foo/bar
                    301:foo/bar
                    300:foo/doe
    201   HS_VLIST  300:foo/admin
                    301:foo/admin
    300   HS_SECKEY *myadminpassword*
    301   HS_PUBKEY 0000B652300
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/bar:**

    ===== ========= =======================
    Index Key       Value
    ...   ...       ...
    100   HS_ADMIN  (refers to 201:foo/admin)
    300   HS_SECKEY *mypassword*
    301   HS_PUBKEY 0000A552100
     ...  ...       ...
    ===== ========= =======================

    **Handle record foo/doe:**

    ===== ========= =======================
    Index Key       Value
    ...   ...       ...
    100   HS_ADMIN  (refers to 201:foo/admin)
    300   HS_SECKEY *mypassword*
     ...  ...       ...
    ===== ========= =======================

