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

#define MAX_BUFFER_LENGTH        20

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
