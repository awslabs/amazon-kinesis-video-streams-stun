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

#define MAX_BUFFER_LENGTH        512

void setUp( void )
{
}

void tearDown( void )
{
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
    uint8_t buffer[ MAX_BUFFER_LENGTH ];
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
                                  &( buffer[ 0 ] ),
                                  MAX_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( buffer[ 0 ] ),
                           ctx.pStart );
    TEST_ASSERT_EQUAL( MAX_BUFFER_LENGTH,
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
    uint8_t buffer[ MAX_BUFFER_LENGTH ];

    result = StunSerializer_Init( NULL,
                                  &( buffer[ 0 ] ),
                                  MAX_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunSerializer_Init( &( ctx ),
                                  &( buffer[ 0 ] ),
                                  MAX_BUFFER_LENGTH,
                                  NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    result = StunSerializer_Init( &( ctx ),
                                  &( buffer[ 0 ] ),
                                  10, /* Buffer length less than STUN_HEADER_LENGTH. */
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode in the happy path.
 */
void test_StunSerializer_AddAttributeErrorCode_Pass_( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t buffer[ MAX_BUFFER_LENGTH ] = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] = { 0x12, 0x34, 0x56,
                                                                   0x78, 0x9A, 0xBC,
                                                                   0xDE, 0xF0, 0xAB,
                                                                   0xCD, 0xEF, 0xA5 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorPhraseLength = strlen( ( const char * ) errorPhrase );
    uint16_t errorCode = 0x0600;
    size_t expectedLength;
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 20. */
        0x00, 0x01, 0x00, 0x14,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Error Code, Attribute Length = 20 */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0, Error Code = 600 */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase */
        0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x50, 0x68, 0x72, 0x61, 0x73, 0x65
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  &( buffer[0] ),
                                  MAX_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   &( errorPhrase[0] ),
                                                   errorPhraseLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( expectedLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( expectedStunMessage,
                                   buffer,
                                   expectedStunMessageLength );

    TEST_ASSERT_EQUAL( expectedLength,
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
                                                   &( errorPhrase[0] ),
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
    uint8_t buffer[ MAX_BUFFER_LENGTH ] = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] = { 0x12, 0x34, 0x56,
                                                                   0x78, 0x9A, 0xBC,
                                                                   0xDE, 0xF0, 0xAB,
                                                                   0xCD, 0xEF, 0xA5 };
    uint16_t errorCode = 0x0600; 

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  &( buffer[0] ),
                                  MAX_BUFFER_LENGTH,
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
    uint8_t buffer[ MAX_BUFFER_LENGTH ] = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] = { 0x12, 0x34, 0x56,
                                                                   0x78, 0x9A, 0xBC,
                                                                   0xDE, 0xF0, 0xAB,
                                                                   0xCD, 0xEF, 0xA5 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorCode = 0x0600; 

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  &( buffer[0] ),
                                  MAX_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

     result = StunSerializer_AddAttributeErrorCode( NULL,
                                                   errorCode,
                                                   &( errorPhrase[0] ),
                                                   0);

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode when pCtx->pStart is null.
 */
void test_StunSerializer_AddAttributeErrorCode_pStartNull( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t buffer[ MAX_BUFFER_LENGTH ] = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] = { 0x12, 0x34, 0x56,
                                                                   0x78, 0x9A, 0xBC,
                                                                   0xDE, 0xF0, 0xAB,
                                                                   0xCD, 0xEF, 0xA5 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorPhraseLength = sizeof(errorPhrase );
    uint16_t errorCode = 0x0600;

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

     result = StunSerializer_Init( &( ctx ),
                                  &( buffer[0] ),
                                  MAX_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    ctx.pStart = NULL; /* Set pCtx->pStart to NULL */

    result = StunSerializer_AddAttributeErrorCode( &(ctx),
                                                   errorCode,
                                                   &(errorPhrase[0]),
                                                   errorPhraseLength );
                                                   
    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
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
    uint8_t buffer[ 20 ] = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] = { 0x12, 0x34, 0x56,
                                                                   0x78, 0x9A, 0xBC,
                                                                   0xDE, 0xF0, 0xAB,
                                                                   0xCD, 0xEF, 0xA5 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Error Phrase";
    uint16_t errorPhraseLength = strlen( ( const char * ) errorPhrase );
    uint16_t errorCode = 0x0600;

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  &( buffer[0] ),
                                  20,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   &( errorPhrase[0] ),
                                                   errorPhraseLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_AddAttributeErrorCode in case of short error phrase.
 */
void test_StunSerializer_AddAttributeErrorCode_Short( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t buffer[ MAX_BUFFER_LENGTH ] = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] = { 0x12, 0x34, 0x56,
                                                                   0x78, 0x9A, 0xBC,
                                                                   0xDE, 0xF0, 0xAB,
                                                                   0xCD, 0xEF, 0xA5 };
    const uint8_t * errorPhrase = ( const uint8_t * ) "Short";
    uint16_t errorPhraseLength = strlen( ( const char * ) errorPhrase );
    uint16_t errorCode = 0x0600;
    size_t expectedLength;
    uint8_t expectedStunMessage[] =
    {
        /* Message Type = STUN Binding Request, Message Length = 20. */
        0x00, 0x01, 0x00, 0x10,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5,
        /* Attribute Type = Error Code, Attribute Length = 20 */
        0x00, 0x09, 0x00, 0x09,
        /* Reserved = 0, Error Code = 600 */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase */
        0x53, 0x68, 0x6F, 0x72, 0x74, 0x00, 0x00, 0x00
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[ 0 ] );

    result = StunSerializer_Init( &( ctx ),
                                  &( buffer[0] ),
                                  MAX_BUFFER_LENGTH,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_AddAttributeErrorCode( &( ctx ),
                                                   errorCode,
                                                   &( errorPhrase[0] ),
                                                   errorPhraseLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    result = StunSerializer_Finalize( &( ctx ),
                                      &( expectedLength ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( expectedStunMessage,
                                   buffer,
                                   expectedStunMessageLength );

    TEST_ASSERT_EQUAL( expectedLength,
                       expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

