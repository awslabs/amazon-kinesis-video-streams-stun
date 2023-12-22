
#ifndef STUN_DESERIALIZER_H
#define STUN_DESERIALIZER_H

#include "stun_data_types.h"

StunResult_t StunDeserializer_Init( StunContext_t * pCtx,
                                    const uint8_t * pStunMessage,
                                    size_t stunMessageLength );

StunResult_t StunDeserializer_GetHeader( StunContext_t * pCtx,
                                         StunHeader_t * pStunHeader );

StunResult_t StunDeserializer_GetNextAttribute( StunContext_t * pCtx,
                                                StunAttribute_t * pAttribute );

StunResult_t StunDeserializer_ParseAttributePriority( const StunAttribute_t * pAttribute,
                                                      uint32_t * pPriority );

StunResult_t StunDeserializer_ParseAttributeUsername( const StunAttribute_t * pAttribute,
                                                      const char ** pUsername,
                                                      uint16_t * pUsernameLength );

/* StunDeserializer_ParseAttributeFingerprint,
 * StunDeserializer_ParseAttributeIntegrity,
 * StunDeserializer_ParseAttributeRealm,
 * StunDeserializer_ParseAttributeNonce,
 *  ... */

#endif /* STUN_DESERIALIZER_H */
