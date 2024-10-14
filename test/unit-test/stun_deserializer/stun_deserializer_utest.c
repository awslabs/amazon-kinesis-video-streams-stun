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
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x00 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x00,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( &( serializedMessage[ 0 ] ),
                       ctx.pStart );
    TEST_ASSERT_EQUAL( serializedMessageLength,
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
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x00. */
        0x00, 0x01, 0x00, 0x00,
        /* Intentionally wrong Magic cookie. */
        0x21, 0x13, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_MAGIC_COOKIE_MISMATCH,
                       result );
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
    uint8_t serializedMessage[ STUN_HEADER_LENGTH ] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x00. */
        0x00, 0x01, 0x00, 0x00,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    size_t serializedMessageLength = STUN_HEADER_LENGTH + 0x70; /* 0x70 is not the payload length
                                                                 * as specified in the header. */

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_INVALID_MESSAGE_LENGTH,
                       result );
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
    StunAttribute_t attribute = { 0 };
    uint8_t * errorPhrase = NULL;
    uint16_t errorPhraseLength, errorCode, channelNumber;
    uint64_t iceControlled;
    uint32_t lifetime, numAttributes = 0;;
    uint8_t serializedMessage[] =
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
        /* Reserved = 0x0000, Error Class = 6, Error Number = 0 (Error Code = 600). */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase = "Error Phrase". */
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
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
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
            numAttributes++;

            switch( attribute.attributeType )
            {
                case STUN_ATTRIBUTE_TYPE_ERROR_CODE:
                {
                    result = StunDeserializer_ParseAttributeErrorCode( &( attribute ),
                                                                       &( errorCode ),
                                                                       &( errorPhrase ),
                                                                       &( errorPhraseLength ) );
                    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                       result );
                    TEST_ASSERT_EQUAL( 600,
                                       errorCode );
                    TEST_ASSERT_EQUAL_STRING_LEN( "Error Phrase",
                                                  &( errorPhrase [ 0 ] ),
                                                  errorPhraseLength );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER:
                {
                    result = StunDeserializer_ParseAttributeChannelNumber( &( ctx ),
                                                                           &( attribute ),
                                                                           &( channelNumber ) );

                    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                       result );
                    TEST_ASSERT_EQUAL( 0x1234,
                                       channelNumber );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_LIFETIME:
                {
                    result = StunDeserializer_ParseAttributeLifetime( &( ctx ),
                                                                      &( attribute ),
                                                                      &( lifetime ) );

                    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                       result );
                    TEST_ASSERT_EQUAL( 0x0000EA60,
                                       lifetime );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED:
                {
                    result = StunDeserializer_ParseAttributeIceControlled( &( ctx ),
                                                                           &( attribute ),
                                                                           &( iceControlled ) );

                    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                       result );
                    TEST_ASSERT_EQUAL( 0x1234567890ABCDEF,
                                       iceControlled );
                }
                break;

                default:
                {
                    TEST_FAIL_MESSAGE( "Unexpected attribute type!" );
                }
                break;
            }
        }
    }

    TEST_ASSERT_EQUAL( 4,
                       numAttributes );
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
    StunAttribute_t attribute = { 0 };
    uint32_t priority, changeFlag;
    uint32_t crc32Fingerprint, numAttributes = 0;
    uint64_t iceControlling;
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x24 (excluding 20 bytes header). */
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
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
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
            numAttributes++;

            switch( attribute.attributeType )
            {
                case STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST:
                {
                    result = StunDeserializer_ParseAttributeChangeRequest( &( ctx ),
                                                                           &( attribute ),
                                                                           &( changeFlag ) );

                    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                       result );
                    TEST_ASSERT_EQUAL( 0x00000004,
                                       changeFlag );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_PRIORITY:
                {
                    result = StunDeserializer_ParseAttributePriority( &( ctx ),
                                                                      &( attribute ),
                                                                      &( priority ) );

                    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                       result );
                    TEST_ASSERT_EQUAL( 0x6E000100,
                                       priority );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING:
                {
                    result = StunDeserializer_ParseAttributeIceControlling( &( ctx ),
                                                                            &( attribute ),
                                                                            &( iceControlling ) );

                    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                       result );
                    TEST_ASSERT_EQUAL( 0x0123456789ABCDEF,
                                       iceControlling );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_FINGERPRINT:
                {
                    result = StunDeserializer_ParseAttributeFingerprint( &( ctx ),
                                                                         &( attribute ),
                                                                         &( crc32Fingerprint ) );

                    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                                       result );
                    TEST_ASSERT_EQUAL( 0x54DA6D71,
                                       crc32Fingerprint );
                }
                break;

                default:
                {
                    TEST_FAIL_MESSAGE( "Unexpected attribute type!" );
                }
                break;
            }
        }
    }

    TEST_ASSERT_EQUAL( 4,
                       numAttributes );
    TEST_ASSERT_EQUAL( STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute incase of null context.
 */
void test_StunDeserializer_GetNextAttribute_NullContext( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };

    result = StunDeserializer_GetNextAttribute( NULL,
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute incase of null attribute.
 */
void test_StunDeserializer_GetNextAttribute_NullAttribute( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeErrorCode incase of null attribute.
 */
void test_StunDeserializer_ParseAttributeErrorCode_NullAttribute( void )
{
    StunResult_t result;
    uint8_t * errorPhrase = NULL;
    uint16_t errorPhraseLength, errorCode;

    result = StunDeserializer_ParseAttributeErrorCode( NULL,
                                                       &( errorCode ),
                                                       &( errorPhrase ),
                                                       &( errorPhraseLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeErrorCode incase of null error code.
 */
void test_StunDeserializer_ParseAttributeErrorCode_NullErrorCode( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t * errorPhrase = NULL;
    uint16_t errorPhraseLength;

    result = StunDeserializer_ParseAttributeErrorCode( &( attribute ),
                                                       NULL,
                                                       &( errorPhrase ),
                                                       &( errorPhraseLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeErrorCode incase of wrong attribute type.
 */
void test_StunDeserializer_ParseAttributeErrorCode_WrongAttributeType( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t * errorPhrase = NULL;
    uint16_t errorPhraseLength, errorCode;
    uint8_t attributeValue[] =
    {
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x50, 0x68, 0x72, 0x61, 0x73, 0x65,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY; /* Not error code. */
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeErrorCode( &( attribute ),
                                                       &( errorCode ),
                                                       &( errorPhrase ),
                                                       &( errorPhraseLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeErrorCode incase of null attribute value.
 */
void test_StunDeserializer_ParseAttributeErrorCode_NullAttributeValue( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t * errorPhrase = NULL;
    uint16_t errorPhraseLength, errorCode;
    uint8_t attributeValue[] =
    {
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x50, 0x68, 0x72, 0x61, 0x73, 0x65,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_ERROR_CODE;
    attribute.pAttributeValue = NULL;
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeErrorCode( &( attribute ),
                                                       &( errorCode ),
                                                       &( errorPhrase ),
                                                       &( errorPhraseLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeErrorCode incase of incorrect attributeValueLength.
 */
void test_StunDeserializer_ParseAttributeErrorCode_IncorrectAttributeValueLength( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t * errorPhrase = NULL;
    uint16_t errorPhraseLength, errorCode;
    uint8_t attributeValue[] =
    {
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x50, 0x68, 0x72, 0x61, 0x73, 0x65,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_ERROR_CODE;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = 1;

    result = StunDeserializer_ParseAttributeErrorCode( &( attribute ),
                                                       &( errorCode ),
                                                       &( errorPhrase ),
                                                       &( errorPhraseLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeChannelNumber incase of null channel number.
 */
void test_StunDeserializer_ParseAttributeChannelNumber_NullChannelNumber( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t attributeValue[] =
    {
        /* Channel Number = 0x1234, Reserved = 0x0000. */
        0x12, 0x34, 0x00, 0x00,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeChannelNumber( &( ctx ),
                                                           &( attribute ),
                                                           NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeChannelNumber incase of null attribute.
 */
void test_StunDeserializer_ParseAttributeChannelNumber_NullAttribute( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    uint16_t channelNumber = 0;

    result = StunDeserializer_ParseAttributeChannelNumber( &( ctx ),
                                                           NULL,
                                                           &( channelNumber ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeChannelNumber incase of wrong attribute type.
 */
void test_StunDeserializer_ParseAttributeChannelNumber_WrongAttributeType( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint16_t channelNumber = 0;
    uint8_t attributeValue[] =
    {
        /* Channel Number = 0x1234, Reserved = 0x0000. */
        0x12, 0x34, 0x00, 0x00,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_ERROR_CODE; /* Not Channel Number. */
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeChannelNumber( &( ctx ),
                                                           &( attribute ),
                                                           &( channelNumber ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeChannelNumber incase of null attributeValue.
 */
void test_StunDeserializer_ParseAttributeChannelNumber_NullAttributeValue( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint16_t channelNumber = 0;
    uint8_t attributeValue[] =
    {
        /* Channel Number = 0x1234, Reserved = 0x0000. */
        0x12, 0x34, 0x00, 0x00,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER;
    attribute.pAttributeValue = NULL;
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeChannelNumber( &( ctx ),
                                                           &( attribute ),
                                                           &( channelNumber ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeChannelNumber incase of invalid attribute length.
 */
void test_StunDeserializer_ParseAttributeChannelNumber_InvalidAttributeLength( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint16_t channelNumber = 0;
    uint8_t attributeValue[] =
    {
        /* Channel Number = 0x1234, Reserved = 0x0000. */
        0x12, 0x34, 0x00, 0x00,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue ) - 1; /* Invalid attribute length. */

    result = StunDeserializer_ParseAttributeChannelNumber( &( ctx ),
                                                           &( attribute ),
                                                           &( channelNumber ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_INVALID_ATTRIBUTE_LENGTH,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributePriority incase of null priority.
 */
void test_StunDeserializer_ParseAttributePriority_NullPriority( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t attributeValue[] =
    {
        /* Attribute Value: 0x6E000100 (Priority = 2023406816). */
        0x6E, 0x00, 0x01, 0x00,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_PRIORITY;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributePriority( &( ctx ),
                                                      &( attribute ),
                                                      NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributePriority incase of null attribute.
 */
void test_StunDeserializer_ParseAttributePriority_NullAttribute( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    uint32_t priority = 0;

    result = StunDeserializer_ParseAttributePriority( &( ctx ),
                                                      NULL,
                                                      &( priority ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributePriority incase of wrong attribute type.
 */
void test_StunDeserializer_ParseAttributePriority_WrongAttributeType( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint32_t priority = 0;
    uint8_t attributeValue[] =
    {
        /* Attribute Value: 0x6E000100 (Priority = 2023406816). */
        0x6E, 0x00, 0x01, 0x00,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_ERROR_CODE; /* Not priority type. */
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributePriority( &( ctx ),
                                                      &( attribute ),
                                                      &( priority ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributePriority incase of null attributeValue.
 */
void test_StunDeserializer_ParseAttributePriority_NullAttributeValue( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint32_t priority = 0;
    uint8_t attributeValue[] =
    {
        /* Attribute Value: 0x6E000100 (Priority = 2023406816). */
        0x6E, 0x00, 0x01, 0x00,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_PRIORITY;
    attribute.pAttributeValue = NULL;
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributePriority( &( ctx ),
                                                      &( attribute ),
                                                      &( priority ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributePriority incase of invalid attribute length.
 */
void test_StunDeserializer_ParseAttributePriority_InvalidAttributeLength( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint32_t priority = 0;
    uint8_t attributeValue[] =
    {
        /* Attribute Value: 0x6E000100 (Priority = 2023406816). */
        0x6E, 0x00, 0x01, 0x00,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_PRIORITY;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue ) - 1; /* Invalid attribute length. */

    result = StunDeserializer_ParseAttributePriority( &( ctx ),
                                                      &( attribute ),
                                                      &( priority ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_INVALID_ATTRIBUTE_LENGTH,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeFingerprint incase of null attribute.
 */
void test_StunDeserializer_ParseAttributeFingerprint_NullAttribute( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    uint32_t crc32Fingerprint = 0;

    result = StunDeserializer_ParseAttributeFingerprint( &( ctx ),
                                                         NULL,
                                                         &( crc32Fingerprint ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeIceControlled incase of null iceControlled value.
 */
void test_StunDeserializer_ParseAttributeIceControlled_NullIceControlledValue( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t attributeValue[] =
    {
        /* Attribute Value = 0x1234567890ABCDE. */
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xAB, 0xCD, 0xEF,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeIceControlled( &( ctx ),
                                                           &( attribute ),
                                                           NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeIceControlled incase of null attribute.
 */
void test_StunDeserializer_ParseAttributeIceControlled_NullAttribute( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    uint64_t iceControlledValue = 0;

    result = StunDeserializer_ParseAttributeIceControlled( &( ctx ),
                                                           NULL,
                                                           &( iceControlledValue ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeIceControlled incase of wrong attribute type.
 */
void test_StunDeserializer_ParseAttributeIceControlled_WrongAttributeType( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint64_t iceControlledValue = 0;
    uint8_t attributeValue[] =
    {
        /* Attribute Value = 0x1234567890ABCDE. */
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xAB, 0xCD, 0xEF,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_ERROR_CODE; /* Not ice controlled type. */
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeIceControlled( &( ctx ),
                                                           &( attribute ),
                                                           &( iceControlledValue ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeIceControlled incase of null attributeValue.
 */
void test_StunDeserializer_ParseAttributeIceControlled_NullAttributeValue( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint64_t iceControlledValue = 0;
    uint8_t attributeValue[] =
    {
        /* Attribute Value = 0x1234567890ABCDE. */
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xAB, 0xCD, 0xEF,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED;
    attribute.pAttributeValue = NULL;
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeIceControlled( &( ctx ),
                                                           &( attribute ),
                                                           &( iceControlledValue ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeIceControlled incase of invalid attribute length.
 */
void test_StunDeserializer_ParseAttributeIceControlled_InvalidAttributeLength( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint64_t iceControlledValue = 0;
    uint8_t attributeValue[] =
    {
        /* Attribute Value = 0x1234567890ABCDE. */
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xAB, 0xCD, 0xEF,
    };

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue ) - 1; /* Invalid attribute length. */

    result = StunDeserializer_ParseAttributeIceControlled( &( ctx ),
                                                           &( attribute ),
                                                           &( iceControlledValue ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_INVALID_ATTRIBUTE_LENGTH,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetFingerprintBuffer in the happy path.
 */
void test_StunDeserializer_GetFingerprintBuffer_HappyPath( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    uint8_t * pFingerprintCalculationData;
    uint16_t fingerprintCalculationDataLength;
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x08 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = FINGERPRINT (0x8028), Attribute Length = 4. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x078E383F (Obtained from XOR of 0x54DA6D71 and STUN_ATTRIBUTE_FINGERPRINT_XOR_VALUE). */
        0x07, 0x8E, 0x38, 0x3F,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_FINGERPRINT,
                       attribute.attributeType );

    result = StunDeserializer_GetFingerprintBuffer( &( ctx ),
                                                    &( pFingerprintCalculationData ),
                                                    &( fingerprintCalculationDataLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 20, /* Stun message excluding fingerprint attribute. */
                       fingerprintCalculationDataLength );
    TEST_ASSERT_EQUAL_PTR( &( serializedMessage[ 0 ] ),
                           pFingerprintCalculationData );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( serializedMessage[ 0 ] ),
                                   pFingerprintCalculationData,
                                   fingerprintCalculationDataLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetFingerprintBuffer in case of null parameters.
 */
void test_StunDeserializer_GetFingerprintBuffer_NullParams( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    uint8_t * pFingerprintCalculationData;
    uint16_t fingerprintCalculationDataLength;

    result = StunDeserializer_GetFingerprintBuffer( NULL,
                                                    &( pFingerprintCalculationData ),
                                                    &( fingerprintCalculationDataLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunDeserializer_GetFingerprintBuffer( &( ctx ),
                                                    NULL,
                                                    &( fingerprintCalculationDataLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunDeserializer_GetFingerprintBuffer( &( ctx ),
                                                    &( pFingerprintCalculationData ),
                                                    NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetIntegrityBuffer in the happy path.
 */
void test_StunDeserializer_GetIntegrityBuffer_HappyPath( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    uint8_t * pHmacCalculationData;
    uint16_t hmacCalculationDataLength;
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x18 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x18,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = 20 bytes SHA-1 HMAC value. */
        0x72, 0x64, 0x6D, 0x2F,
        0x55, 0x77, 0xF4, 0x23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0xAB, 0xCD, 0xDE, 0xEF,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY,
                       attribute.attributeType );

    result = StunDeserializer_GetIntegrityBuffer( &( ctx ),
                                                  &( pHmacCalculationData ),
                                                  &( hmacCalculationDataLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 20, /* Stun message excluding integrity attribute. */
                       hmacCalculationDataLength );
    TEST_ASSERT_EQUAL_PTR( &( serializedMessage[ 0 ] ),
                           pHmacCalculationData );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( serializedMessage[ 0 ] ),
                                   pHmacCalculationData,
                                   hmacCalculationDataLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetIntegrityBuffer in case of null parameters.
 */
void test_StunDeserializer_GetIntegrityBuffer_NullParams( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    uint8_t * pHmacCalculationData;
    uint16_t hmacCalculationDataLength;

    result = StunDeserializer_GetIntegrityBuffer( NULL,
                                                  &( pHmacCalculationData ),
                                                  &( hmacCalculationDataLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunDeserializer_GetIntegrityBuffer( &( ctx ),
                                                  NULL,
                                                  &( hmacCalculationDataLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunDeserializer_GetIntegrityBuffer( &( ctx ),
                                                  &( pHmacCalculationData ),
                                                  NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_UpdateAttributeNonce in the happy path.
 */
void test_StunDeserializer_UpdateAttributeNonce_HappyPath( void )
{
    StunResult_t result;
    StunAttribute_t attribute;
    uint8_t attributeValue[] =
    {
        /* Attribute Value = 0x123456789ABCDEF0. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    };
    uint8_t updatedNonce[] =
    {
        0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x1A, 0x2A, 0x3A
    };
    uint16_t updatedNonceLength = sizeof( updatedNonce );

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_NONCE;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_UpdateAttributeNonce( &( updatedNonce[ 0 ] ),
                                                    updatedNonceLength,
                                                    &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( updatedNonce[ 0 ] ),
                                   attribute.pAttributeValue,
                                   updatedNonceLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_UpdateAttributeNonce in case of bad parameters.
 */
void test_StunDeserializer_UpdateAttributeNonce_BadParams( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t updatedNonce[] =
    {
        0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x1A, 0x2A, 0x3A
    };
    uint16_t updatedNonceLength = sizeof( updatedNonce );

    result = StunDeserializer_UpdateAttributeNonce( NULL,
                                                    updatedNonceLength,
                                                    &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunDeserializer_UpdateAttributeNonce( &( updatedNonce[ 0 ] ),
                                                    updatedNonceLength,
                                                    NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_UpdateAttributeNonce in case of wrong attribute type.
 */
void test_StunDeserializer_UpdateAttributeNonce_WrongAttributeType( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t attributeValue[] =
    {
        /* Attribute Value = 0x123456789ABCDEF0. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    };
    uint8_t updatedNonce[] =
    {
        0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x1A, 0x2A, 0x3A
    };
    uint16_t updatedNonceLength = sizeof( updatedNonce );

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_FINGERPRINT; /* Not nonce. */
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_UpdateAttributeNonce( &( updatedNonce[ 0 ] ),
                                                    updatedNonceLength,
                                                    &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_UpdateAttributeNonce in case of invalid nonce length.
 */
void test_StunDeserializer_UpdateAttributeNonce_InvalidNonceLength( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    uint8_t attributeValue[] =
    {
        /* Attribute Value = 0x123456789ABCDEF0. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    };
    /* Updated nonce is not of the same length as the original one. */
    uint8_t updatedNonce[] =
    {
        0xAB, 0xBC, 0xCD, 0xDE,
    };
    uint16_t updatedNonceLength = sizeof( updatedNonce );

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_NONCE;
    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_UpdateAttributeNonce( &( updatedNonce[ 0 ] ),
                                                    updatedNonceLength,
                                                    &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeAddress incase of happy path.
 */
void test_StunDeserializer_ParseAttributeAddress_HappyPath( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    StunAttributeAddress_t parsedAddress = { 0 };
    uint8_t expectedAddress[] = { 0x7F, 0x00, 0x00, 0x01, };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x0C (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x0C,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = MAPPED-ADDRESS (0x0001), Attribute Length = 8. */
        0x00, 0x01, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x1234, IP Address = 0x7F000001 (127.0.0.1). */
        0x00, 0x01, 0x12, 0x34, 0x7F, 0x00, 0x00, 0x01,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS,
                       attribute.attributeType );

    result = StunDeserializer_ParseAttributeAddress( &( ctx ),
                                                     &( attribute ),
                                                     &( parsedAddress ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ADDRESS_IPv4,
                       parsedAddress.family );
    TEST_ASSERT_EQUAL( 0x1234,
                       parsedAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedAddress[ 0 ] ),
                                   &( parsedAddress.address[ 0 ] ),
                                   4 );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeAddress in case of null parameters.
 */
void test_StunDeserializer_ParseAttributeAddress_NullParams( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };
    StunAttributeAddress_t parsedAddress = { 0 };
    uint8_t attributeValue[] =
    {
        0x00, 0x01, 0x12, 0x34, 0x7F, 0x00, 0x00, 0x01,
    };

    result = StunDeserializer_ParseAttributeAddress( &( ctx ),
                                                     NULL,
                                                     &( parsedAddress ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS;
    attribute.pAttributeValue = NULL;
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeAddress( &( ctx ),
                                                     &( attribute ),
                                                     &( parsedAddress ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    attribute.pAttributeValue = &( attributeValue[ 0 ] );
    attribute.attributeValueLength = sizeof( attributeValue );

    result = StunDeserializer_ParseAttributeAddress( &( ctx ),
                                                     &( attribute ),
                                                     NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeAddress (XOR Mapped Type) incase of happy path.
 */
void test_StunDeserializer_ParseAttributeAddress_XorMapped_HappyPath( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    StunAttributeAddress_t parsedAddress = { 0 };
    uint8_t expectedAddress[] = { 0x7F, 0x00, 0x00, 0x01 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x0C (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x0C,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = XOR-MAPPED-ADDRESS (0x0020), Attribute Length = 8. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3326 (0x1234 XOR'd with 2 msb of cookie),
         * IP Address = 0x5E12A443 (127.0.0.1 XOR'd with cookie). */
        0x00, 0x01, 0x33, 0x26, 0x5E, 0x12, 0xA4, 0x43,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS,
                       attribute.attributeType );

    result = StunDeserializer_ParseAttributeAddress( &( ctx ),
                                                     &( attribute ),
                                                     &( parsedAddress ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ADDRESS_IPv4,
                       parsedAddress.family );
    TEST_ASSERT_EQUAL( 0x1234,
                       parsedAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedAddress[ 0 ] ),
                                   &( parsedAddress.address[ 0 ] ),
                                   4 );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeAddress (XOR Relayed Type) incase of happy path.
 */
void test_StunDeserializer_ParseAttributeAddress_XorRelayed_HappyPath( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    StunAttributeAddress_t parsedAddress = { 0 };
    uint8_t expectedAddress[] = { 0x7F, 0x00, 0x00, 0x01 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x0C (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x0C,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = XOR-RELAYED-ADDRESS (0x0016), Attribute Length = 8. */
        0x00, 0x16, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3326 (0x1234 XOR'd with 2 msb of cookie),
         * IP Address = 0x5E12A443 (127.0.0.1 XOR'd with cookie). */
        0x00, 0x01, 0x33, 0x26, 0x5E, 0x12, 0xA4, 0x43,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS,
                       attribute.attributeType );

    result = StunDeserializer_ParseAttributeAddress( &( ctx ),
                                                     &( attribute ),
                                                     &( parsedAddress ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ADDRESS_IPv4,
                       parsedAddress.family );
    TEST_ASSERT_EQUAL( 0x1234,
                       parsedAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedAddress[ 0 ] ),
                                   &( parsedAddress.address[ 0 ] ),
                                   4 );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeAddress (XOR Peer Type) incase of happy path.
 */
void test_StunDeserializer_ParseAttributeAddress_XorPeer_HappyPath( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    StunAttributeAddress_t parsedAddress = { 0 };
    uint8_t expectedAddress[] = { 0x7F, 0x00, 0x00, 0x01 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x0C (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x0C,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = XOR-PEER-ADDRESS (0x0012), Attribute Length = 8. */
        0x00, 0x12, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3326 (0x1234 XOR'd with 2 msb of cookie),
         * IP Address = 0x5E12A443 (127.0.0.1 XOR'd with cookie). */
        0x00, 0x01, 0x33, 0x26, 0x5E, 0x12, 0xA4, 0x43,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS,
                       attribute.attributeType );

    result = StunDeserializer_ParseAttributeAddress( &( ctx ),
                                                     &( attribute ),
                                                     &( parsedAddress ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ADDRESS_IPv4,
                       parsedAddress.family );
    TEST_ASSERT_EQUAL( 0x1234,
                       parsedAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedAddress[ 0 ] ),
                                   &( parsedAddress.address[ 0 ] ),
                                   4 );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_ParseAttributeAddress (IPv6 Type) incase of happy path.
 */
void test_StunDeserializer_ParseAttributeAddress_IPv6_HappyPath( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    StunAttributeAddress_t parsedAddress = { 0 };
    uint8_t expectedAddress[] =
    {
        0x01, 0x13, 0xA9, 0xFA,
        0x97, 0x97, 0x56, 0x78,
        0x9A, 0xBC, 0x54, 0xDE,
        0xA8, 0xBD, 0x9C, 0x91,
    };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x18 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x18,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = XOR-MAPPED-ADDRESS (0x0020), Attribute Length = 20. */
        0x00, 0x20, 0x00, 0x14,
        /* Address family = IPv6, Port = 0x3326 (0x1234 XOR'd with 2 msb of cookie),
         * IP Address = 2001:0DB8:85A3:0000:0000:8A2E:0370:7334 (0113:A9FA:9797:5678:9ABC:54DE:A8BD:9C91
         * XOR'd with cookie and transaction ID). */
        0x00, 0x02, 0x33, 0x26,
        0x20, 0x01, 0x0D, 0xB8,
        0x85, 0xA3, 0x00, 0x00,
        0x00, 0x00, 0x8A, 0x2E,
        0x03, 0x70, 0x73, 0x34,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS,
                       attribute.attributeType );

    result = StunDeserializer_ParseAttributeAddress( &( ctx ),
                                                     &( attribute ),
                                                     &( parsedAddress ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ADDRESS_IPv6,
                       parsedAddress.family );
    TEST_ASSERT_EQUAL( 0x1234,
                       parsedAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedAddress[ 0 ] ),
                                   &( parsedAddress.address[ 0 ] ),
                                   16 );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_FindAttribute in case of different attribute types.
 *
 * It includes the following scenarios:
 *
 * 1. Trying to find the STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED attribute, which is not
 *    present in the STUN message, and expecting the function to return
 *    STUN_RESULT_NO_ATTRIBUTE_FOUND.
 * 2. Finding the STUN_ATTRIBUTE_TYPE_PRIORITY attribute, which is present in the
 *    STUN message, and verifying that the function returns STUN_RESULT_OK.
 */
void test_StunDeserializer_FindAttribute( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x08 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = PRIORITY (0x0024), Attribute Length = 4. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value: 0x6E000100 (Priority = 2023406816). */
        0x6E, 0x00, 0x01, 0x00,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );
    uint8_t expectedAttributeValue[] =
    {
        /* Priority attribute value = 0x6E000100. */
        0x6E, 0x00, 0x01, 0x00,
    };
    size_t expectedAttributeValueLength = sizeof( expectedAttributeValue );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_FindAttribute( &( ctx ),
                                             STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED,
                                             &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_NO_ATTRIBUTE_FOUND,
                       result );

    result = StunDeserializer_FindAttribute( &( ctx ),
                                             STUN_ATTRIBUTE_TYPE_PRIORITY,
                                             &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_PRIORITY,
                       attribute.attributeType );
    TEST_ASSERT_EQUAL( expectedAttributeValueLength,
                       attribute.attributeValueLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedAttributeValue[ 0 ] ),
                                   attribute.pAttributeValue,
                                   expectedAttributeValueLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_FindAttribute in case of null attribute.
 */
void test_StunDeserializer_FindAttribute_NullAttribute( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x08 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = PRIORITY (0x0024), Attribute Length = 4. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value: 0x6E000100 (Priority = 2023406816). */
        0x6E, 0x00, 0x01, 0x00,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_FindAttribute( &( ctx ),
                                             STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED,
                                             NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_FindAttribute in case of null context.
 */
void test_StunDeserializer_FindAttribute_NullContext( void )
{
    StunResult_t result;
    StunAttribute_t attribute = { 0 };

    result = StunDeserializer_FindAttribute( NULL,
                                             STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED,
                                             &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_FindAttribute in case of null StunContext_t.pStart.
 */
void test_StunDeserializer_FindAttribute_NullContextStart( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunAttribute_t attribute = { 0 };

    ctx.pStart = NULL;

    result = StunDeserializer_FindAttribute( &( ctx ),
                                             STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED,
                                             &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute incase of invalid attribute order.
 */
void test_StunDeserializer_GetNextAttribute_InvalidAttributeOrder( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x20 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x20,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = FINGERPRINT (0x8028), Attribute Length = 4. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x078E383F (Obtained from XOR of 0x54DA6D71 and STUN_ATTRIBUTE_FINGERPRINT_XOR_VALUE). */
        0x07, 0x8E, 0x38, 0x3F,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = 20 bytes SHA-1 HMAC value. */
        0x72, 0x64, 0x6D, 0x2F,
        0x55, 0x77, 0xF4, 0x23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0xAB, 0xCD, 0xDE, 0xEF,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    /* First attribute is FINGERPRINT. */
    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_FINGERPRINT,
                       attribute.attributeType );

    /* Next attribute is the Message-Integrity attribute. However, this is an
     * invalid order, as Message-Integrity must come before Fingerprint. */
    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_INVALID_ATTRIBUTE_ORDER,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute incase of invalid attribute order.
 */
void test_StunDeserializer_GetNextAttribute_InvalidAttributeOrder_2( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x20 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x20,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = 20 bytes SHA-1 HMAC value. */
        0x72, 0x64, 0x6D, 0x2F,
        0x55, 0x77, 0xF4, 0x23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0xAB, 0xCD, 0xDE, 0xEF,
        /* Attribute Type = PRIORITY (0x0024), Attribute Length = 4. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value: 0x6E000100 (Priority = 2023406816). */
        0x6E, 0x00, 0x01, 0x00,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    /* First attribute is Message-Integrity. */
    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY,
                       attribute.attributeType );

    /* Next attribute is the Priority. However, this is an invalid order, as
     * Priority must come before Message-Integrity. Only Fingerprint attribute
     * can come after the Message-Integrity attribute. */
    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_INVALID_ATTRIBUTE_ORDER,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute incase of valid attribute order.
 */
void test_StunDeserializer_GetNextAttribute_ValidAttributeOrder( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    uint32_t crc32Fingerprint;
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x20 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x20,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = 20 bytes SHA-1 HMAC value. */
        0x72, 0x64, 0x6D, 0x2F,
        0x55, 0x77, 0xF4, 0x23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0xAB, 0xCD, 0xDE, 0xEF,
        /* Attribute type = FINGERPRINT (0x8028), Attribute Length = 4. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x078E383F (Obtained from XOR of 0x54DA6D71 and STUN_ATTRIBUTE_FINGERPRINT_XOR_VALUE). */
        0x07, 0x8E, 0x38, 0x3F,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    /* First attribute is Message-Integrity. */
    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY,
                       attribute.attributeType );

    /* Next attribute is Fingerprint. */
    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_FINGERPRINT,
                       attribute.attributeType );

    result = StunDeserializer_ParseAttributeFingerprint( &( ctx ),
                                                         &( attribute ),
                                                         &( crc32Fingerprint ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 0x54DA6D71,
                       crc32Fingerprint );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute in case of zero attributeValueLength.
 */
void test_StunDeserializer_GetNextAttribute_ZeroAttributeValueLength( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x04 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x04,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0. */
        0x00, 0x25, 0x00, 0x00,
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( STUN_ATTRIBUTE_TYPE_USE_CANDIDATE,
                       attribute.attributeType );
    TEST_ASSERT_EQUAL( 0,
                       attribute.attributeValueLength );
    TEST_ASSERT_EQUAL( NULL,
                       attribute.pAttributeValue );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunDeserializer_GetNextAttribute in case of out of memory.
 */
void test_StunDeserializer_GetNextAttribute_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    StunAttribute_t attribute = { 0 };
    uint8_t serializedMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x04 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x04,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = PRIORITY (0x0024), Attribute Length = 4. */
        0x00, 0x24, 0x00, 0x04,
        /* Missing priority value. */
    };
    size_t serializedMessageLength = sizeof( serializedMessage );

    result = StunDeserializer_Init( &( ctx ),
                                    &( serializedMessage[ 0 ] ),
                                    serializedMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunDeserializer_GetNextAttribute( &( ctx ),
                                                &( attribute ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/
