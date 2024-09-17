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
 * @brief Validate Validate StunDeserializer_Init incase of happy path.
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
    uint8_t serializedHeader[ STUN_HEADER_LENGTH ] =
    {
        /* Message Type = STUN Binding Request, Message Length = 0x80. */
        0x00, 0x01, 0x00, 0x80,
        /* Magic cookie. */
        0x21, 0x12, 0xA4, 0x42,
        /* Transaction ID. */
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xAB, 0xCD, 0xEF, 0xA5
    };
    size_t stunMessageLength = STUN_HEADER_LENGTH + 0x80; /* 0x80 is the payload length
                                                           * as specified in the header. */

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
 * @brief Validate Validate StunDeserializer_Init incase of bad parameters.
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
