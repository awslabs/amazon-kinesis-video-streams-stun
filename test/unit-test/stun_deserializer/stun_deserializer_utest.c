/* Unity includes. */
#include "unity.h"
#include "catch_assert.h"

/* Standard includes. */
#include <string.h>
#include <stdint.h>

/* API includes. */
#include "stun_deserializer.h"
#include "stun_endianness.h"
#include "stun_data_types.h"

/* ===========================  EXTERN VARIABLES  =========================== */

void setUp( void )
{
}

void tearDown( void )
{
}

/* ==============================  Test Cases ============================== */

/**
 * @brief Validate StunDeserializer_Init incase of happy path.
 */

void test_StunDeserializer_Init_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] = { 0x12, 0x34, 0x56,
                                                                   0x78, 0x9A, 0xBC,
                                                                   0xDE, 0xF0, 0xAB,
                                                                   0xCD, 0xEF, 0xA5 };
    uint8_t serializedHeader[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x00 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x00,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
    };
    size_t stunMessageLength = sizeof( serializedHeader );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedHeader[ 0 ] ),
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( &( serializedHeader[ 0 ] ),
                       ctx.pStart );
    TEST_ASSERT_EQUAL( stunMessageLength,
                       ctx.totalLength );
    TEST_ASSERT_EQUAL( STUN_HEADER_LENGTH,
                       ctx.currentIndex );
    TEST_ASSERT_EQUAL( 0,
                       ctx.attributeFlag );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint16Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint32Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint64Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint16Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint32Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint64Fn );
    TEST_ASSERT_EQUAL( STUN_MESSAGE_TYPE_BINDING_REQUEST,
                       header.messageType );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( transactionId[ 0 ] ),
                                   header.pTransactionId,
                                   STUN_HEADER_TRANSACTION_ID_LENGTH );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_Init incase of bad parameters.
 */
void test_StunDeserializer_Init_BadParams( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t stunMessage[ STUN_HEADER_LENGTH ];

    result = StunDeserializer_Init( NULL,
                                    &( stunMessage[ 0 ] ),
                                    STUN_HEADER_LENGTH,
                                    &( header ) );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_BAD_PARAM,
                           result );

    result = StunDeserializer_Init( &( ctx ),
                                    NULL,
                                    STUN_HEADER_LENGTH,
                                    &( header ) );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_BAD_PARAM,
                           result );

    result = StunDeserializer_Init( &( ctx ),
                                    &( stunMessage[ 0 ] ),
                                    10, /* Message length less than STUN_HEADER_LENGTH. */
                                    &( header ) );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_BAD_PARAM,
                           result );

    result = StunDeserializer_Init( &( ctx ),
                                    &( stunMessage [ 0 ] ),
                                    STUN_HEADER_LENGTH,
                                    NULL );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_BAD_PARAM,
                           result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_Init incase of Magic Cookie Mismatch.
 */

void test_StunDeserializer_Init_MagicCookieMismatch( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t serializedHeader[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x00. */
        0x00, 0x01, 0x00, 0x00,
        /* Intentionally wrong Magic cookie. */
        0x21, 0x13, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    size_t stunMessageLength = sizeof( serializedHeader );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedHeader[ 0 ] ),
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_MAGIC_COOKIE_MISMATCH,
                       result );
    TEST_ASSERT_EQUAL( &( serializedHeader[ 0 ] ),
                       ctx.pStart );
    TEST_ASSERT_EQUAL( stunMessageLength,
                       ctx.totalLength );
    TEST_ASSERT_EQUAL( 0,
                       ctx.currentIndex );
    TEST_ASSERT_EQUAL( 0,
                       ctx.attributeFlag );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint16Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint32Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint64Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint16Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint32Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint64Fn );
    TEST_ASSERT_EQUAL( STUN_MESSAGE_TYPE_BINDING_REQUEST,
                       header.messageType );
    TEST_ASSERT_NULL( header.pTransactionId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_Init incase of invalid message length.
 */

void test_StunDeserializer_Init_InvalidMessageLength( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t serializedHeader[ STUN_HEADER_LENGTH ] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x00. */
        0x00, 0x01, 0x00, 0x00,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    size_t stunMessageLength = STUN_HEADER_LENGTH + 0x70; /* 0x70 is not the payload length
                                                           * as specified in the header. */

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedHeader[ 0 ] ),
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_INVALID_MESSAGE_LENGTH,
                       result );
    TEST_ASSERT_EQUAL( &( serializedHeader[ 0 ] ),
                       ctx.pStart );
    TEST_ASSERT_EQUAL( stunMessageLength,
                       ctx.totalLength );
    TEST_ASSERT_EQUAL( 0,
                       ctx.currentIndex );
    TEST_ASSERT_EQUAL( 0,
                       ctx.attributeFlag );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint16Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint32Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.readUint64Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint16Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint32Fn );
    TEST_ASSERT_NOT_NULL( ctx.readWriteFunctions.writeUint64Fn );
    TEST_ASSERT_EQUAL( STUN_MESSAGE_TYPE_BINDING_REQUEST,
                       header.messageType );
    TEST_ASSERT_NULL( header.pTransactionId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute incase of happy path.
 */
void test_StunDeserializer_GetNextAttribute_IceControlled( void )
{

    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t serializedHeader[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x30 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x30,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes,
         * 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Code = 0x0600. */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase. */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute Type = Channel Number (0x000C), Attribute Length = 4. */
        0x00, 0x0C, 0x00, 0x04,
        /* Channel Number = 0x1234, Reserved = 0x0000. */
        0x12, 0x34, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Attribute Length = 4. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0x0000EA60 (60000 seconds in hex). */
        0x00, 0x00, 0xEA, 0x60,
        /* Attribute type = ICE-CONTROLLED (0x8029), Attribute Length = 8. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x1234567890ABCDE. */
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xAB, 0xCD, 0xEF,
    };
    size_t stunMessageLength = sizeof( serializedHeader );
    StunAttribute_t attribute = { 0 };
    uint8_t * errorPhrase = NULL;
    uint16_t errorPhraseLength, errorCode, channelNumber;
    uint64_t iceControlled;
    uint32_t lifetime;

    result = StunDeserializer_Init( &( ctx ),
                                    serializedHeader,
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    while( result != STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND )
    {
        TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                           result );

        result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                    &( attribute ) );

        if( result == STUN_RESULT_OK )
        {
            switch( attribute.attributeType )
            {

            case STUN_ATTRIBUTE_TYPE_ERROR_CODE:
                result = StunDeserializer_ParseAttributeErrorCode( &( attribute ),
                                                                   &( errorCode ),
                                                                   &( errorPhrase ),
                                                                   &( errorPhraseLength ) );

                TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                   result );

                TEST_ASSERT_EQUAL( 600,
                                   errorCode );

                TEST_ASSERT_EQUAL_STRING_LEN( "Error Phrase",
                                              &( errorPhrase [0] ),
                                              errorPhraseLength );
                break;

            case STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER:
                result = StunDeserializer_ParseAttributeChannelNumber( &( ctx ),
                                                                       &( attribute ),
                                                                       &( channelNumber ) );

                TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                   result );

                TEST_ASSERT_EQUAL( 0x1234,
                                   channelNumber );
                break;

            case STUN_ATTRIBUTE_TYPE_LIFETIME:
                result = StunDeserializer_ParseAttributeLifetime( &( ctx ),
                                                                  &( attribute ),
                                                                  &( lifetime ) );

                TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                   result );

                TEST_ASSERT_EQUAL( 0x0000EA60,
                                   lifetime );
                break;

            case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED:
                result = StunDeserializer_ParseAttributeIceControlled( &( ctx ),
                                                                       &( attribute ),
                                                                       &( iceControlled ) );

                TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                   result );

                TEST_ASSERT_EQUAL( 0x1234567890ABCDEF,
                                   iceControlled );
                break;

            default:
                TEST_FAIL_MESSAGE( "Unexpected attribute type" );
                break;
            }
        }

    }

    TEST_ASSERT_EQUAL( STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND,
                       result );

}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute incase of happy path.
 */
void test_StunDeserializer_GetNextAttribute_IceControlling( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t serializedHeader[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x20 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x24,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = CHANGE-REQUEST (0x0003), Attribute Length = 4. */
        0x00, 0x03, 0x00, 0x04,
        /* Attribute Value: 0x00000004 (Change IP flag). */
        0x00, 0x00, 0x00, 0x04,
        /* Attribute Type = PRIORITY (0x0024), Attribute Length = 4. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value: 0x6E000100 (Priority = 2023406816). */
        0x6E, 0x00, 0x01, 0x00,
        /* Attribute Type = ICE-CONTROLLING (0x802A), Attribute Length = 8. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value: 0x0123456789ABCDEF (ICE-CONTROLLING value). */
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        /* Attribute type = FINGERPRINT (0x8028), Attribute Length = 4. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x078E383F (Obtained from XOR of 0x54DA6D71 and STUN_ATTRIBUTE_FINGERPRINT_XOR_VALUE). */
        0x07, 0x8E, 0x38, 0x3F,
    };
    size_t stunMessageLength = sizeof( serializedHeader );
    StunAttribute_t attribute = { 0 };
    uint32_t priority, changeFlag;
    uint32_t crc32Fingerprint;
    uint64_t iceControlling;

    result = StunDeserializer_Init( &( ctx ),
                                    serializedHeader,
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    while( result != STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND )
    {
        TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                           result );

        result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                    &( attribute ) );

        if( result == STUN_RESULT_OK )
        {
            switch( attribute.attributeType )
            {
            case STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST:
                result = StunDeserializer_ParseAttributeChangeRequest( &( ctx ),
                                                                       &( attribute ),
                                                                       &( changeFlag ) );

                TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                   result );

                TEST_ASSERT_EQUAL( 0x00000004,
                                   changeFlag );
                break;

            case STUN_ATTRIBUTE_TYPE_PRIORITY:
                result = StunDeserializer_ParseAttributePriority( &( ctx ),
                                                                  &( attribute ),
                                                                  &( priority ) );

                TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                   result );

                TEST_ASSERT_EQUAL( 0x6E000100,
                                   priority );
                break;

            case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING:
                result = StunDeserializer_ParseAttributeIceControlling( &( ctx ),
                                                                        &( attribute ),
                                                                        &( iceControlling ) );

                TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                   result );

                TEST_ASSERT_EQUAL( 0x0123456789ABCDEF,
                                   iceControlling );
                break;

            case STUN_ATTRIBUTE_TYPE_FINGERPRINT:
                result = StunDeserializer_ParseAttributeFingerprint( &( ctx ),
                                                                     &( attribute ),
                                                                     &( crc32Fingerprint ) );
                                                                     
                TEST_ASSERT_EQUAL( 0x54DA6D71,
                                   crc32Fingerprint );
                break;

            default:
                TEST_FAIL_MESSAGE( "Unexpected attribute type" );
                break;

            }
        }

    }

    TEST_ASSERT_EQUAL( STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND,
                       result );
}