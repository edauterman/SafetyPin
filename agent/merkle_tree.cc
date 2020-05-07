#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#include "common.h"
#include "merkle_tree.h"

Node *Node_new() {
   Node *n = (Node *)malloc(sizeof(Node));
   n->rightChild = NULL;
   n->leftChild = NULL;
   n->parent = NULL;
   return n;
}

void Node_free(Node *n) {
    if (n->rightChild != NULL) Node_free(n->rightChild);
    if (n->leftChild != NULL) Node_free(n->leftChild);
    if (n->parent != NULL) Node_free(n->parent);
    free(n);
}

MerkleProof *MerkleProof_new() {
    return (MerkleProof *)malloc(sizeof(MerkleProof));
}

void MerkleProof_free(MerkleProof *p) {
    free(p);
}

void MerkleTree_CopyNodeHash(uint8_t *dst, Node *n) {
    if (n != NULL) {
        memcpy(dst, n->hash, SHA256_DIGEST_LENGTH);
    } else {
        memset(dst, 0, SHA256_DIGEST_LENGTH);
    }
}

Node *MerkleTree_CreateNewParent(Node *leftChild, Node *rightChild) {
    int rv;
    EVP_MD_CTX *mdctx;
    Node *parent;

    mdctx = EVP_MD_CTX_create();
    parent = Node_new();
    parent->rightChild = rightChild;
    parent->leftChild = leftChild;
    parent->leftID = leftChild->leftID;
    parent->rightID = rightChild->rightID;
    parent->midID = rightChild->leftID;

    uint8_t buf[SHA256_DIGEST_LENGTH * 2];
    MerkleTree_CopyNodeHash(buf, leftChild);
    MerkleTree_CopyNodeHash(buf + SHA256_DIGEST_LENGTH, rightChild);

    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, buf, 2 * SHA256_DIGEST_LENGTH));
    CHECK_C (EVP_DigestFinal_ex(mdctx, parent->hash, NULL));

    rightChild->parent = parent;
    leftChild->parent = parent;

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    return parent;
}

Node *MerkleTree_CreateNewLeaf(int id, uint8_t *value) {
    Node *leaf = Node_new();
    memcpy(leaf->hash, value, SHA256_DIGEST_LENGTH);
    leaf->id = id;
    leaf->leftID = id;
    leaf->midID = id;
    leaf->rightID = id;
    return leaf;
}

int MerkleTree_UpdateRightChild(Node *parent, Node *rightChild) {
    int rv;
    EVP_MD_CTX *mdctx;
    
    mdctx = EVP_MD_CTX_create();
    parent->rightChild = rightChild;
    parent->rightID = rightChild->rightID;
    parent->midID = rightChild->leftID;
    rightChild->parent = parent;

    uint8_t buf[SHA256_DIGEST_LENGTH * 2];
    MerkleTree_CopyNodeHash(buf, parent->leftChild);
    MerkleTree_CopyNodeHash(buf + SHA256_DIGEST_LENGTH, rightChild);

    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, buf, 2 * SHA256_DIGEST_LENGTH));
    CHECK_C (EVP_DigestFinal_ex(mdctx, parent->hash, NULL));

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);    
    return rv;
}

int MerkleTree_UpdateLeftChild(Node *parent, Node *leftChild) {
    int rv;
    EVP_MD_CTX *mdctx;
    
    mdctx = EVP_MD_CTX_create();
    parent->leftChild = leftChild;
    parent->leftID = leftChild->leftID;
    leftChild->parent = parent;

    uint8_t buf[SHA256_DIGEST_LENGTH * 2];
    MerkleTree_CopyNodeHash(buf, leftChild);
    MerkleTree_CopyNodeHash(buf + SHA256_DIGEST_LENGTH, parent->rightChild);

    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, buf, 2 * SHA256_DIGEST_LENGTH));
    CHECK_C (EVP_DigestFinal_ex(mdctx, parent->hash, NULL));

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);    
    return rv;
}

Node *MerkleTree_GetLeafForId(Node *head, int id) {
    Node *curr = head;
    while (curr->id != id) {
        if (id < curr->midID) {
            curr = curr->leftChild;
        } else {
            curr = curr->rightChild;
        }
        if (curr == NULL) return NULL;  // ID not present.
    }
    return curr;
}

MerkleProof *MerkleTree_GetProof(Node *head, int id) {
    MerkleProof *proof = MerkleProof_new();
    Node *curr = head;
    int ctr = 0;
    while (curr->id != id) {
        if (id < curr->midID) {
            MerkleTree_CopyNodeHash(proof->hash[ctr], curr->rightChild);
            proof->goRight[ctr] = false;
            curr = curr->leftChild;
        } else {
            MerkleTree_CopyNodeHash(proof->hash[ctr], curr->leftChild);
            proof->goRight[ctr] = true;
            curr = curr->rightChild;
        }
        ctr++;
        if (curr == NULL) return NULL;  // ID not present.
    }
    proof->len = ctr;
    memcpy(proof->head, head->hash, SHA256_DIGEST_LENGTH);
    return proof;
}

int MerkleTree_InsertLeaf(Node *head, int id, uint8_t *value) {
    Node *leaf = MerkleTree_CreateNewLeaf(id, value);
    
    Node *curr = head;
    while (true) {
        if (id < curr->midID) {
            if (curr->leftChild == NULL) break;
            curr = curr->leftChild;
        } else {
            if (curr->rightChild == NULL) break;
            curr = curr->rightChild;
        }
    }

    Node *child = leaf;
    while (curr != NULL) {
        if (id < curr->midID) {
            MerkleTree_UpdateLeftChild(curr, child);
        } else {
            MerkleTree_UpdateRightChild(curr, child);
        }
        child = child->parent;
        curr = curr->parent;
    }
}

Node *MerkleTree_CreateTree(int *ids, uint8_t **values, int len) {
    Node **leaves = (Node **)malloc(len * sizeof(Node *));
    for (int i = 0; i < len; i++) {
        leaves[i] = MerkleTree_CreateNewLeaf(ids[i], values[i]);
    }
    Node **currNodes = leaves;
    Node **parentNodes;
    int currLen = len / 2;
    while (currLen > 0) {
        parentNodes = (Node **)malloc(currLen * sizeof(Node *));
        for (int i = 0; i < currLen; i++) {
            parentNodes[i] = MerkleTree_CreateNewParent(currNodes[2 * i], currNodes[2 * i + 1]);
        }
        currLen /= 2;
        currNodes = parentNodes;
    }
    return currNodes[0];
}

int MerkleTree_VerifyProof(Node *head, MerkleProof *proof, uint8_t *value, int id) {
    int rv;
    EVP_MD_CTX *mdctx;
    uint8_t currHash[SHA256_DIGEST_LENGTH];
    uint8_t nextHash[SHA256_DIGEST_LENGTH];
    uint8_t buf[2 * SHA256_DIGEST_LENGTH];


    mdctx = EVP_MD_CTX_create();
    memcpy(currHash, value, SHA256_DIGEST_LENGTH);

    for (int i = proof->len - 1; i >= 0; i--) {
        CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
        if (proof->goRight[i]) {
            memcpy(buf, proof->hash[i], SHA256_DIGEST_LENGTH);
            memcpy(buf + SHA256_DIGEST_LENGTH, currHash, SHA256_DIGEST_LENGTH);
        } else {
            memcpy(buf, currHash, SHA256_DIGEST_LENGTH);
            memcpy(buf + SHA256_DIGEST_LENGTH, proof->hash[i], SHA256_DIGEST_LENGTH);
        }
        CHECK_C (EVP_DigestUpdate(mdctx, buf, 2 * SHA256_DIGEST_LENGTH));
        CHECK_C (EVP_DigestFinal_ex(mdctx, nextHash, NULL));
        memcpy(currHash, nextHash, SHA256_DIGEST_LENGTH);
    }
    if (memcmp(nextHash, head->hash, SHA256_DIGEST_LENGTH) != 0) return ERROR;

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    return rv;
}
