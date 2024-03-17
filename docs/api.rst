API Reference
=============

.. py:currentmodule:: aioacme

.. autoclass:: Client
   :members:

.. autoclass:: IdentifierType
   :show-inheritance:

   .. autoattribute:: dns

   .. autoattribute:: ip

.. autoclass:: Identifier
   :members:

.. autoclass:: Error
   :members:

.. autoclass:: OrderStatus
   :show-inheritance:

   .. autoattribute:: pending
   .. autoattribute:: ready
   .. autoattribute:: processing
   .. autoattribute:: valid
   .. autoattribute:: invalid

.. autoclass:: Order
   :members:

.. autoclass:: ChallengeType
   :show-inheritance:

   .. autoattribute:: dns01
   .. autoattribute:: http01
   .. autoattribute:: tlsalpn01

.. autoclass:: ChallengeStatus
   :show-inheritance:

   .. autoattribute:: pending
   .. autoattribute:: processing
   .. autoattribute:: valid
   .. autoattribute:: invalid

.. autoclass:: Challenge
   :members:

.. autoclass:: AuthorizationStatus
   :show-inheritance:

   .. autoattribute:: pending
   .. autoattribute:: valid
   .. autoattribute:: invalid
   .. autoattribute:: expired
   .. autoattribute:: deactivated

.. autoclass:: Authorization
   :members:

.. autoclass:: RevocationReason
   :show-inheritance:

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
