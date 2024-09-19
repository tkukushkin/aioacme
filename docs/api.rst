API Reference
=============

.. py:currentmodule:: aioacme

.. py:data:: LETS_ENCRYPT_STAGING_DIRECTORY
   :annotation: = 'https://acme-staging-v02.api.letsencrypt.org/directory'

   The Let's Encrypt staging directory URL.


.. py:data:: LETS_ENCRYPT_DIRECTORY
   :annotation: = 'https://acme-v02.api.letsencrypt.org/directory'

   The Let's Encrypt directory URL.


.. py:data:: ZEROSSL_DIRECTORY
   :annotation: = 'https://acme.zerossl.com/v2/DV90'

   ZeroSSL directory URL.

.. autoclass:: Client
   :members:
   :undoc-members:
   :special-members: __aenter__, __aexit__

.. autoclass:: AccountStatus()
   :show-inheritance:

   .. autoattribute:: valid
   .. autoattribute:: deactivated
   .. autoattribute:: revoked

.. autoclass:: Account()
   :members:
   :undoc-members:

.. autoclass:: IdentifierType()
   :show-inheritance:

   .. autoattribute:: dns
   .. autoattribute:: ip

.. autoclass:: Identifier()
   :members:
   :undoc-members:

.. autoclass:: Error()
   :members:
   :undoc-members:

.. autoclass:: OrderStatus()
   :show-inheritance:
   :undoc-members:

   .. autoattribute:: pending
   .. autoattribute:: ready
   .. autoattribute:: processing
   .. autoattribute:: valid
   .. autoattribute:: invalid

.. autoclass:: Order()
   :members:
   :undoc-members:

.. autoclass:: ChallengeType()
   :show-inheritance:
   :undoc-members:

   .. autoattribute:: dns01
   .. autoattribute:: dnsaccount01
   .. autoattribute:: http01
   .. autoattribute:: tlsalpn01

.. autoclass:: ChallengeStatus()
   :show-inheritance:
   :undoc-members:

   .. autoattribute:: pending
   .. autoattribute:: processing
   .. autoattribute:: valid
   .. autoattribute:: invalid

.. autoclass:: Challenge()
   :members:
   :undoc-members:

.. autoclass:: AuthorizationStatus()
   :show-inheritance:
   :undoc-members:

   .. autoattribute:: pending
   .. autoattribute:: valid
   .. autoattribute:: invalid
   .. autoattribute:: expired
   .. autoattribute:: deactivated

.. autoclass:: Authorization()
   :members:
   :undoc-members:

.. autoclass:: RevocationReason()
   :show-inheritance:
   :undoc-members:

   .. autoattribute:: unspecified
   .. autoattribute:: key_compromise
   .. autoattribute:: ca_compromise
   .. autoattribute:: affiliation_changed
   .. autoattribute:: superseded
   .. autoattribute:: cessation_of_operation
   .. autoattribute:: certificate_hold
   .. autoattribute:: remove_from_crl
   .. autoattribute:: privilege_withdrawn
   .. autoattribute:: aa_compromise

.. autoclass:: ExternalAccountBinding()
   :members:
   :undoc-members:

.. autoexception:: AcmeError()
   :members:
   :undoc-members:
