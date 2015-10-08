#ifndef SECURITY_LEVEL_H
#define SECURITY_LEVEL_H

/**
* Many cryptographic primitives and schemes have different security levels.
* For example, an encryption scheme can be CPA-secure (secure against chosen-plaintext attacks)
* or CCA-secure (secure against chosen-ciphertext attacks).
* The security level of a cryptographic entity is specified by making the implementing class of the entity
* declare that it implements a certain security level; for example, an encryption scheme that is CCA-secure will implement the Cca interface.
* Different primitives have different families that define their security levels (e.g., hash functions, MACs, encryption).
* It is often the case that different security levels of a given primitive form a hierarchy (e.g., any CCA-secure encryption scheme is also CPA-secure),
* and in this case they extend each other. Thus, it suffices to implement a Cca interface and this immediately implies that a Cpa interface is also implied.
* <p>
* All of the interfaces expressing a security level are marker interfaces that define types of security level and do not have any functionality.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/
class SecurityLevel {};

/**
* This hierarchy specifies the security level of a cyclic group in which discrete log hardness is assumed to hold. The levels in this hierarchy are Dlog, CDH and DDH.
*/
class DlogSecLevel : public SecurityLevel {};

/**
* A group in which the discrete log problem is assumed to hold should implement this interface.
*/
class Dlog : public DlogSecLevel {};

/**
* A group in which the computational Diffie-Hellman problem is assumed to hold should implement this interface.
*/
class CDH:public Dlog {};

/**
* A group in which the decisional Diffie-Hellman problem is assumed to hold should implement this interface.
*/
class DDH : public CDH {};

/**
* This hierarchy specifies the security level of a cryptographic hash function. The levels in this hierarchy are TargetCollisionResistant and CollisionResistant.
*/
class HashSecLevel : public SecurityLevel {};

#endif