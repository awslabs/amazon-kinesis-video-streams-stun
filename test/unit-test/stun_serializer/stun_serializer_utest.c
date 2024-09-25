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
    uint16_t errorCode = 0x0600;
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
        /* Reserved = 0x0000, Error Code = 0x0600. */
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
    uint16_t errorCode = 0x0600;

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
    uint16_t errorCode = 0x0600;
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
    uint16_t errorCode = 0x0600;
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
    uint16_t errorCode = 0x0600;
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
        /* Reserved = 0x0000, Error Code = 0x0600. */
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
    uint16_t errorCode = 0x0600;
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
        /* Reserved = 0x0000, Error Code = 0x0600. */
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

