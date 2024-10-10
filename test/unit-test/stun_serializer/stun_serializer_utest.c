/* Unity includes. */
#include "unity.h"
#include "catch_assert.h"

/* Standard includes. */
#include <string.h>
#include <stdint.h>

/* API includes. */
#include "stun_serializer.h"
#include "stun_endianness.h"
#include "stun_data_types.h"

/* ===========================  EXTERN VARIABLES  =========================== */

#define GUARD_LENGTH                32
#define STUN_MESSAGE_BUFFER_LENGTH  512

uint8_t stunMessageBuffer[ GUARD_LENGTH + STUN_MESSAGE_BUFFER_LENGTH + GUARD_LENGTH ];
uint8_t * pStunMessageBuffer = NULL;

void setUp( void )
{
    memset( &( stunMessageBuffer[ 0 ] ),
            0xA5,
            GUARD_LENGTH );

    memset( &( stunMessageBuffer[ GUARD_LENGTH ] ),
            0,
            STUN_MESSAGE_BUFFER_LENGTH );

    memset( &( stunMessageBuffer[ GUARD_LENGTH + STUN_MESSAGE_BUFFER_LENGTH ] ),
            0xA5,
            GUARD_LENGTH );

    pStunMessageBuffer = &( stunMessageBuffer[ GUARD_LENGTH ] );
}

void tearDown( void )
{
    TEST_ASSERT_EACH_EQUAL_UINT8( 0xA5,
                                  &( stunMessageBuffer[ 0 ] ),
                                  GUARD_LENGTH );

    TEST_ASSERT_EACH_EQUAL_UINT8( 0xA5,
                                  &( stunMessageBuffer[ GUARD_LENGTH + STUN_MESSAGE_BUFFER_LENGTH ] ),
                                  GUARD_LENGTH );
}

/* ==============================  Test Cases ============================== */

/**
 * @brief Validate StunSerializer_Init in the happy path.
 */
void test_StunSerializer_Init_Pass( void )
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
        /* Message Type = STUN Binding Request, Message Length = 0. */
        0x00, 0x01, 0x00, 0x00,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL_PTR( pStunMessageBuffer,
                           ctx.pStart );
    TEST_ASSERT_EQUAL( STUN_MESSAGE_BUFFER_LENGTH,
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
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( serializedHeader[ 0 ] ),
                                   ctx.pStart,
                                   STUN_HEADER_LENGTH );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_Init in case of NULL buffer.
 */
void test_StunSerializer_Init_NullBuffer( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  0,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL_PTR( NULL,
                           ctx.pStart );
    TEST_ASSERT_EQUAL( 0,
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
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_Init incase of bad parameters.
 */
void test_StunSerializer_Init_BadParams( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };

    result = StunSerializer_Init( NULL,
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  10, /* Buffer length less than STUN_HEADER_LENGTH. */
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode in the happy path.
 */
void test_StunSerializer_AddAttributeErrorCode_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorPhraseLength = strlen( ( const char * ) errorPhrase );
    uint16_t errorCode = 600;
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 20 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x14,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes,
         * 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 6, Error Number = 0 (Error Code = 600). */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase. */
        0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x50, 0x68, 0x72, 0x61, 0x73, 0x65
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   &( errorPhrase[ 0 ] ),
                                                   errorPhraseLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode with NULL context.
 */
void test_StunSerializer_AddAttributeErrorCode_NullContext( void )
{
    StunResult_t result;
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorPhraseLength = strlen( ( const char * ) errorPhrase );
    uint16_t errorCode = 600;

    result = StunSerializer_AddAttributeErrorCode( NULL,
                                                   errorCode,
                                                   &( errorPhrase[ 0 ] ),
                                                   errorPhraseLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode with NULL error phrase.
 */
void test_StunSerializer_AddAttributeErrorCode_NullErrorPhrase( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint16_t errorCode = 600;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   NULL,
                                                   0 );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode with zero error phrase length.
 */
void test_StunSerializer_AddAttributeErrorCode_ZeroErrorPhraseLength( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorCode = 600;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   &( errorPhrase[0] ),
                                                   0 );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode when buffer is null.
 */
void test_StunSerializer_AddAttributeErrorCode_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorPhraseLength = strlen( ( const char * ) errorPhrase );;
    uint16_t errorCode = 600;
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 20 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x14,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes,
         * 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 6, Error Number = 0 (Error Code = 600). */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase. */
        0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x50, 0x68, 0x72, 0x61, 0x73, 0x65
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   &( errorPhrase[ 0 ] ),
                                                   errorPhraseLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode in case of out of memory.
 */
void test_StunSerializer_AddAttributeErrorCode_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorPhraseLength = strlen( ( const char * ) errorPhrase );
    uint16_t errorCode = 0x0600;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the error attribute) to intentionally
     * trigger an out-of-memory error when attempting to add the error code
     * attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   &( errorPhrase[ 0 ] ),
                                                   errorPhraseLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode in case of error phrase with padding.
 */
void test_StunSerializer_AddAttributeErrorCode_ErrorPhraseWithPadding( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Short";
    uint16_t errorPhraseLength = strlen( ( const char * ) errorPhrase );
    uint16_t errorCode = 600;
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 20 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x10,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 9 (2 reserved bytes,
         * 2 byte error code and 5 byte error phrase). */
        0x00, 0x09, 0x00, 0x09,
        /* Reserved = 0x0000, Error Class = 6, Error Number = 0 (Error Code = 600). */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase - last 3 bytes are padding to ensure word alignment. */
        0x53, 0x68, 0x6F, 0x72, 0x74, 0x00, 0x00, 0x00
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   &( errorPhrase[ 0 ] ),
                                                   errorPhraseLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage [ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeChannelNumber in the happy path.
 */
void test_StunSerializer_AddAttributeChannelNumber_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint16_t channelNumber = 0x1234;
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Channel Number (0x000C), Attribute Length = 4. */
        0x00, 0x0C, 0x00, 0x04,
        /* Channel Number = 0x1234, Reserved = 0x0000. */
        0x12, 0x34, 0x00, 0x00,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeChannelNumber( &( ctx ),
                                                       channelNumber );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeChannelNumber with NULL context.
 */
void test_StunSerializer_AddAttributeChannelNumber_NullContext( void )
{
    StunResult_t result;
    uint16_t channelNumber = 0x1234;

    result = StunSerializer_AddAttributeChannelNumber( NULL,
                                                       channelNumber );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeChannelNumber in case of out of memory.
 */
void test_StunSerializer_AddAttributeChannelNumber_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint16_t channelNumber = 0x1234;

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the channel attribute) to intentionally
     * trigger an out-of-memory error when attempting to add the channel number
     * attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeChannelNumber( &( ctx ),
                                                       channelNumber );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeChannelNumber when buffer is null.
 */
void test_StunSerializer_AddAttributeChannelNumber_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint16_t channelNumber = 0x1234;
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Channel Number (0x000C), Attribute Length = 4. */
        0x00, 0x0C, 0x00, 0x04,
        /* Channel Number = 0x1234, Reserved = 0x0000. */
        0x12, 0x34, 0x00, 0x00,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeChannelNumber( &( ctx ),
                                                       channelNumber );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUseCandidate in the happy path.
 */
void test_StunSerializer_AddAttributeUseCandidate_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 4 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x04,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Use Candidate (0x0025), Attribute Length = 0. */
        0x00, 0x25, 0x00, 0x00,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUseCandidate( &( ctx ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUseCandidate with a NULL context.
 */
void test_StunSerializer_AddAttributeUseCandidate_NullContext( void )
{
    StunResult_t result;

    result = StunSerializer_AddAttributeUseCandidate( NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUseCandidate in case of out of memory.
 */
void test_StunSerializer_AddAttributeUseCandidate_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the use candidate attribute) to
     * intentionally trigger an out-of-memory error when attempting to add the
     * use candidate attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUseCandidate( &( ctx ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUseCandidate when buffer is null.
 */
void test_StunSerializer_AddAttributeUseCandidate_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 4 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x04,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Use Candidate (0x0025), Attribute Length = 0. */
        0x00, 0x25, 0x00, 0x00,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUseCandidate( &( ctx ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeDontFragment in the happy path.
 */
void test_StunSerializer_AddAttributeDontFragment_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 4 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x04,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Dont fragment (0x001A), Attribute Length = 0. */
        0x00, 0x1A, 0x00, 0x00,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeDontFragment( &( ctx ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeDontFragment with a NULL context.
 */
void test_StunSerializer_AddAttributeDontFragment_NullContext( void )
{
    StunResult_t result;

    result = StunSerializer_AddAttributeDontFragment( NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeDontFragment in case of out of memory.
 */
void test_StunSerializer_AddAttributeDontFragment_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the dont fragment attribute) to
     * intentionally trigger an out-of-memory error when attempting to add the
     * dont fragment attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeDontFragment( &( ctx ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeDontFragment when buffer is null.
 */
void test_StunSerializer_AddAttributeDontFragment_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 4 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x04,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Dont fragment (0x001A), Attribute Length = 0 */
        0x00, 0x1A, 0x00, 0x00
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeDontFragment( &( ctx ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributePriority in the happy path.
 */
void test_StunSerializer_AddAttributePriority_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint32_t priority = 0x6E7F1A2B;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Priority (0x0024), Attribute Length = 4. */
        0x00, 0x24, 0x00, 0x04,
        /* Priority Value = 0x6E7F1A2B. */
        0x6E, 0x7F, 0x1A, 0x2B,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributePriority( &( ctx ),
                                                  priority );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributePriority with a NULL context.
 */
void test_StunSerializer_AddAttributePriority_NullContext( void )
{
    StunResult_t result;
    uint32_t priority = 0x6E7F1A2B;

    result = StunSerializer_AddAttributePriority( NULL,
                                                  priority );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributePriority in case of out of memory.
 */
void test_StunSerializer_AddAttributePriority_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint32_t priority = 0x6E7F1A2B;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the priority attribute) to intentionally
     * trigger an out-of-memory error when attempting to add the priority
     * attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributePriority( &( ctx ),
                                                  priority );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeDontFragment when buffer is null.
 */
void test_StunSerializer_AddAttributePriority_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint32_t priority = 0x6E7F1A2B;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Priority (0x0024), Attribute Length = 4. */
        0x00, 0x24, 0x00, 0x04,
        /* Priority Value = 0x6E7F1A2B. */
        0x6E, 0x7F, 0x1A, 0x2B
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributePriority( &( ctx ),
                                                  priority );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeFingerprint in the happy path.
 */
void test_StunSerializer_AddAttributeFingerprint_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint32_t crc32Fingerprint = 0x54DA6D71;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
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
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeFingerprint( &( ctx ),
                                                     crc32Fingerprint );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeFingerprint with a NULL context.
 */
void test_StunSerializer_AddAttributeFingerprint_NullContext( void )
{
    StunResult_t result;
    uint32_t crc32Fingerprint = 0x54DA6D71;

    result = StunSerializer_AddAttributeFingerprint( NULL,
                                                     crc32Fingerprint );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeFingerprint in case of out of memory.
 */
void test_StunSerializer_AddAttributeFingerprint_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint32_t crc32Fingerprint = 0x54DA6D71;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the fingerprint attribute) to intentionally
     * trigger an out-of-memory error when attempting to add the fingerprint
     * attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeFingerprint( &( ctx ),
                                                     crc32Fingerprint );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeFingerprint when buffer is null.
 */
void test_StunSerializer_AddAttributeFingerprint_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint32_t crc32Fingerprint = 0x54DA6D71;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
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
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeFingerprint( &( ctx ),
                                                     crc32Fingerprint );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeLifetime in the happy path.
 */
void test_StunSerializer_AddAttributeLifetime_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint32_t lifetime = 0x0000EA60; /* 60000 seconds. */
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = LIFETIME (0x000D), Attribute Length = 4. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0x0000EA60 (60000 seconds in hex). */
        0x00, 0x00, 0xEA, 0x60,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeLifetime( &( ctx ),
                                                  lifetime );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeLifetime with a NULL context.
 */
void test_StunSerializer_AddAttributeLifetime_NullContext( void )
{
    StunResult_t result;
    uint32_t lifetime = 0x0000EA60; /* 60000 seconds. */

    result = StunSerializer_AddAttributeLifetime( NULL,
                                                  lifetime );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeLifetime in case of out of memory.
 */
void test_StunSerializer_AddAttributeLifetime_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint32_t lifetime = 0x0000EA60; /* 60000 seconds. */
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the lifetime attribute) to intentionally
     * trigger an out-of-memory error when attempting to add the lifetime
     * attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeLifetime( &( ctx ),
                                                  lifetime );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeLifetime when buffer is null.
 */
void test_StunSerializer_AddAttributeLifetime_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint32_t lifetime = 0x0000EA60; /* 60000 seconds. */
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = LIFETIME (0x000c), Attribute Length = 4. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0x0000EA60 (60000 seconds in hex). */
        0x00, 0x00, 0xEA, 0x60,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeLifetime( &( ctx ),
                                                  lifetime );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeChangeRequest in the happy path.
 */
void test_StunSerializer_AddAttributeChangeRequest_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint32_t changeFlag = 0x00000004; /* Change IP flag (0x00000004). */
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = CHANGE-REQUEST (0x0003), Attribute Length = 4. */
        0x00, 0x03, 0x00, 0x04,
        /* Attribute Value: 0x00000004 (Change IP flag). */
        0x00, 0x00, 0x00, 0x04,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeChangeRequest( &( ctx ),
                                                       changeFlag );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeChangeRequest with a NULL context.
 */
void test_StunSerializer_AddAttributeChangeRequest_NullContext( void )
{
    StunResult_t result;
    uint32_t changeFlag = 0x00000004; /* Change IP flag (0x00000004). */

    result = StunSerializer_AddAttributeChangeRequest( NULL,
                                                       changeFlag );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeChangeRequest in case of out of memory.
 */
void test_StunSerializer_AddAttributeChangeRequest_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint32_t changeFlag = 0x00000004; /* Change IP flag (0x00000004). */
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the change-request attribute) to
     * intentionally trigger an out-of-memory error when attempting to add the
     * change-request attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeChangeRequest( &( ctx ),
                                                       changeFlag );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeChangeRequest when buffer is null.
 */
void test_StunSerializer_AddAttributeChangeRequest_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint32_t changeFlag = 0x00000004; /* Change IP flag (0x00000004). */
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = CHANGE-REQUEST (0x0003), Attribute Length = 4. */
        0x00, 0x03, 0x00, 0x04,
        /* Attribute Value: 0x00000004 (Change IP flag). */
        0x00, 0x00, 0x00, 0x04,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeChangeRequest( &( ctx ),
                                                       changeFlag );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeIceControlled in the happy path.
 */
void test_StunSerializer_AddAttributeIceControlled_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint64_t tieBreaker = 0x1234567890ABCDEF;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 12 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x0C,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = ICE-CONTROLLED (0x8029), Attribute Length = 8. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x1234567890ABCDE. */
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeIceControlled( &( ctx ),
                                                       tieBreaker );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeIceControlled with a NULL context.
 */
void test_StunSerializer_AddAttributeIceControlled_NullContext( void )
{
    StunResult_t result;
    uint64_t tieBreaker = 0x1234567890ABCDEF;

    result = StunSerializer_AddAttributeIceControlled( NULL,
                                                       tieBreaker );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeIceControlled in case of out of memory.
 */
void test_StunSerializer_AddAttributeIceControlled_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint64_t tieBreaker = 0x1234567890ABCDEF;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the ice-controlled attribute) to
     * intentionally trigger an out-of-memory error when attempting to add the
     * ice-controlled attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeIceControlled( &( ctx ),
                                                       tieBreaker );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeIceControlled when buffer is null.
 */
void test_StunSerializer_AddAttributeIceControlled_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint64_t tieBreaker = 0x1234567890ABCDEF;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 12 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x0C,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = ICE-CONTROLLED (0x8029), Attribute Length = 8. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x1234567890ABCDE. */
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeIceControlled( &( ctx ),
                                                       tieBreaker );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeIceControlling in the happy path.
 */
void test_StunSerializer_AddAttributeIceControlling_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint64_t tieBreaker = 0x1234567890ABCDEF;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 12 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x0C,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = ICE-CONTROLLING (0x802A), Attribute Length = 8. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x1234567890ABCDEF. */
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeIceControlling( &( ctx ),
                                                        tieBreaker );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeIceControlling with a NULL context.
 */
void test_StunSerializer_AddAttributeIceControlling_NullContext( void )
{
    StunResult_t result;
    uint64_t tieBreaker = 0x1234567890ABCDEF;

    result = StunSerializer_AddAttributeIceControlling( NULL,
                                                        tieBreaker );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeIceControlling in case of out of memory.
 */
void test_StunSerializer_AddAttributeIceControlling_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint64_t tieBreaker = 0x1234567890ABCDEF;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the ice-controlling attribute) to
     * intentionally trigger an out-of-memory error when attempting to add the
     * ice-controlling attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeIceControlling( &( ctx ),
                                                        tieBreaker );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeIceControlling when buffer is null.
 */
void test_StunSerializer_AddAttributeIceControlling_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    size_t stunMessageLength;
    uint64_t tieBreaker = 0x1234567890ABCDEF;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 12 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x0C,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute type = ICE-CONTROLLING (0x802A), Attribute Length = 8. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x1234567890ABCDEF. */
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeIceControlling( &( ctx ),
                                                        tieBreaker );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUsername in the happy path.
 */
void test_StunSerializer_AddAttributeUsername_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * userName = ( const uint8_t * ) "UserName Tom";
    uint16_t userNameLength = strlen( ( const char * ) userName );
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 16 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x10,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = USERNAME (0x0006), Attribute Length = 12. */
        0x00, 0x06, 0x00, 0x0C,
        /* Attribute Value = "UserName Tom". */
        0x55, 0x73, 0x65, 0x72,
        0x4E, 0x61, 0x6D, 0x65,
        0x20, 0x54, 0x6F, 0x6D,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUsername( &( ctx ),
                                                  userName,
                                                  userNameLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUsername with NULL context.
 */
void test_StunSerializer_AddAttributeUsername_NullContext( void )
{
    StunResult_t result;
    const uint8_t * userName = ( const uint8_t * ) "UserName Tom";
    uint16_t userNameLength = strlen( ( const char * ) userName );

    result = StunSerializer_AddAttributeUsername( NULL,
                                                  userName,
                                                  userNameLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUsername with NULL user name.
 */
void test_StunSerializer_AddAttributeUsername_NullUsername( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUsername( &( ctx ),
                                                  NULL,
                                                  0 );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUsername with zero user name length.
 */
void test_StunSerializer_AddAttributeUsername_ZeroUserNameLength( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * userName = ( const uint8_t * ) "UserName Tom";
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUsername( &( ctx ),
                                                  userName,
                                                  0 );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUsername when buffer is null.
 */
void test_StunSerializer_AddAttributeUsername_BufferNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * userName = ( const uint8_t * ) "UserName Tom";
    uint16_t userNameLength = strlen( ( const char * ) userName );
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 16 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x10,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = USERNAME (0x0006), Attribute Length = 12. */
        0x00, 0x06, 0x00, 0x0C,
        /* Attribute Value = "UserName Tom". */
        0x55, 0x73, 0x65, 0x72,
        0x4E, 0x61, 0x6D, 0x65,
        0x20, 0x54, 0x6F, 0x6D
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUsername( &( ctx ),
                                                  userName,
                                                  userNameLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    /* We should be able to get the correct length of the STUN message. */
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUsername in case of out of memory.
 */
void test_StunSerializer_AddAttributeUsername_OutOfMemory( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * userName = ( const uint8_t * ) "UserName Tom";
    uint16_t userNameLength = strlen( ( const char * ) userName );
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    /* Passing a limited buffer of length 20 bytes (just enough to fit the STUN
     * header and not enough to fit the username attribute) to intentionally
     * trigger an out-of-memory error when attempting to add the username
     * attribute. */
    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUsername( &( ctx ),
                                                  userName,
                                                  userNameLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeUsername in case of user name with padding.
 */
void test_StunSerializer_AddAttributeUsername_UsernameWithPadding( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    const uint8_t * userName = ( const uint8_t * ) "Tom";
    uint16_t userNameLength = strlen( ( const char * ) userName );
    size_t stunMessageLength;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] =
    {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 8 (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = USERNAME (0x0006), Attribute Length = 3. */
        0x00, 0x06, 0x00, 0x03,
        /* Attribute Value = "Tom" with 1 padding byte. */
        0x54, 0x6F, 0x6D, 0x00,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  pStunMessageBuffer,
                                  STUN_MESSAGE_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeUsername( &( ctx ),
                                                  userName,
                                                  userNameLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( stunMessageLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage [ 0 ] ),
                                   pStunMessageBuffer,
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/
