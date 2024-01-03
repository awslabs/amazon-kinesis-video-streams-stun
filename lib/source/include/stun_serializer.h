#ifndef STUN_SERIALIZER_H
#define STUN_SERIALIZER_H

#include "stun_data_types.h"

StunResult_t StunSerializer_Init( StunContext_t * pCtx,
                                  uint8_t * pBuffer,
                                  size_t bufferLength );

StunResult_t StunSerializer_AddHeader( StunContext_t * pCtx,
                                       const StunHeader_t * pHeader );

StunResult_t StunSerializer_AddAttributePriority( StunContext_t * pCtx,
                                                  uint32_t priority );

StunResult_t StunSerializer_AddAttributeUsername( StunContext_t * pCtx,
                                                  const char * pUsername,
                                                  uint16_t usernameLength );

/* StunSerializer_AddAttributeFingerprint,
 * StunSerializer_AddAttributeIntegrity,
 * StunSerializer_AddAttributeRealm,
 * StunSerializer_AddAttributeNonce,
 *  ... */

StunResult_t StunSerializer_Finalize( StunContext_t * pCtx,
                                      const uint8_t ** pStunMessage,
                                      size_t * pStunMessageLength );

#endif /* STUN_SERIALIZER_H */
