#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <openssl/evp.h>
#include "common.h"
#include "merkle_tree.h"

int inline max(int a, int b) {
    return a > b ? a : b;
}

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
//    if (n->parent != NULL) Node_free(n->parent);
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

// rightChild or leftChild can be NULL
Node *MerkleTree_CreateNewParent(Node *leftChild, Node *rightChild, uint64_t maxDiff) {
    int rv;
    EVP_MD_CTX *mdctx;
    Node *parent;

    mdctx = EVP_MD_CTX_create();
    parent = Node_new();
    parent->rightChild = rightChild;
    parent->leftChild = leftChild;
    parent->leftID = leftChild != NULL ? leftChild->leftID : rightChild->rightID - maxDiff + 1;
    parent->rightID = rightChild != NULL ? rightChild->rightID : leftChild->leftID + maxDiff - 1;
    //parent->midID = leftChild != NULL ? leftChild->rightID : rightChild->leftID - 1;
    parent->midID = parent->leftID + maxDiff / 2 - 1;
    //parent->midID = parent->leftID + maxDiff / 2;
    parent->id = -1;

    //printf("node ids = (%ld, %ld, %ld)\n", parent->leftID, parent->midID, parent->rightID);

    uint8_t buf[SHA256_DIGEST_LENGTH * 2];
    MerkleTree_CopyNodeHash(buf, leftChild);
    MerkleTree_CopyNodeHash(buf + SHA256_DIGEST_LENGTH, rightChild);

    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, buf, 2 * SHA256_DIGEST_LENGTH));
    CHECK_C (EVP_DigestUpdate(mdctx, (uint8_t *)&parent->midID, sizeof(uint64_t)));
    CHECK_C (EVP_DigestFinal_ex(mdctx, parent->hash, NULL));

    if (rightChild != NULL) rightChild->parent = parent;
    if (leftChild != NULL) leftChild->parent = parent;

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    return parent;
}

Node *MerkleTree_CreateNewLeaf(uint64_t id, uint8_t *value) {
    Node *leaf = Node_new();
    memcpy(leaf->hash, value, SHA256_DIGEST_LENGTH);
    leaf->id = id;
    leaf->leftID = id;
    leaf->midID = id;
    leaf->rightID = id;
    //printf("leaf ids = (%d, %d, %d)\n", leaf->leftID, leaf->midID, leaf->rightID);
    return leaf;
}

int MerkleTree_UpdateRightChild(Node *parent, Node *rightChild) {
    int rv;
    EVP_MD_CTX *mdctx;
    
    mdctx = EVP_MD_CTX_create();
    parent->rightChild = rightChild;
    //parent->rightID = rightChild->rightID;
    //parent->midID = rightChild->leftID - 1;
    rightChild->parent = parent;

    uint8_t buf[SHA256_DIGEST_LENGTH * 2];
    MerkleTree_CopyNodeHash(buf, parent->leftChild);
    MerkleTree_CopyNodeHash(buf + SHA256_DIGEST_LENGTH, rightChild);

    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, buf, 2 * SHA256_DIGEST_LENGTH));
    CHECK_C (EVP_DigestUpdate(mdctx, (uint8_t *)&parent->midID, sizeof(uint64_t)));
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
    //parent->leftID = leftChild->leftID;
    //parent->midID = leftChild->rightID;
    leftChild->parent = parent;

    uint8_t buf[SHA256_DIGEST_LENGTH * 2];
    MerkleTree_CopyNodeHash(buf, leftChild);
    MerkleTree_CopyNodeHash(buf + SHA256_DIGEST_LENGTH, parent->rightChild);

    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, buf, 2 * SHA256_DIGEST_LENGTH));
    CHECK_C (EVP_DigestUpdate(mdctx, (uint8_t *)&parent->midID, sizeof(uint64_t)));
    CHECK_C (EVP_DigestFinal_ex(mdctx, parent->hash, NULL));

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);    
    return rv;
}

Node *MerkleTree_GetLeafForId(Node *head, uint64_t id) {
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

MerkleProof *MerkleTree_GetProof(Node *head, uint64_t id) {
    MerkleProof *proof = MerkleProof_new();
    Node *curr = head;
    int ctr = 0;
    while (curr->id != id) {
        if (id <= curr->midID) {
            MerkleTree_CopyNodeHash(proof->hash[ctr], curr->rightChild);
            proof->ids[ctr] = curr->midID;
            curr = curr->leftChild;
        } else {
            MerkleTree_CopyNodeHash(proof->hash[ctr], curr->leftChild);
            proof->ids[ctr] = curr->midID;
            curr = curr->rightChild;
        }
        ctr++;
        if (curr == NULL) return NULL;  // ID not present.
    }
    proof->len = ctr;
 
    memcpy(proof->head, head->hash, SHA256_DIGEST_LENGTH);
    memcpy(proof->leaf, curr->hash, SHA256_DIGEST_LENGTH);
    proof->id = id;
    return proof;
}

MerkleProof *MerkleTree_GetEmptyProof(Node *head, uint64_t id) {
    MerkleProof *proof = MerkleProof_new();
    Node *curr = head;
    uint64_t ctr = 0;
    while (curr->id != id) {
        if (id <= curr->midID) {
            MerkleTree_CopyNodeHash(proof->hash[ctr], curr->rightChild);
            proof->ids[ctr] = curr->midID;
            curr = curr->leftChild;
        } else {
            MerkleTree_CopyNodeHash(proof->hash[ctr], curr->leftChild);
            proof->ids[ctr] = curr->midID;
            curr = curr->rightChild;
        }
        ctr++;
        if (curr == NULL) break;  // ID not present.
    }
    proof->len = ctr;
 
    memcpy(proof->head, head->hash, SHA256_DIGEST_LENGTH);
    memset(proof->leaf, 0, SHA256_DIGEST_LENGTH);
    proof->id = id;
    return proof;
}

int MerkleTree_InsertLeaf(Node *head, uint64_t id, uint8_t *value) {
    Node *leaf = MerkleTree_CreateNewLeaf(id, value);
    
    Node *curr = head;
    uint64_t ctr = 0;
    bool done = false;
    while (ctr < MAX_TREE_DEPTH && !done) {
        if (id <= curr->midID) {
            if (curr->leftChild == NULL) {
                done = true;
                break;
            } else {
                curr = curr->leftChild;
            }
        } else {
            if (curr->rightChild == NULL) {
                done = true;
                break;
            } else {
                curr = curr->rightChild;
            }
        }
        if (done) break;
        ctr++;
    }

    Node *child = leaf;
    uint64_t currId = id;
    uint64_t maxDiff = 2;
    for (int i = MAX_TREE_DEPTH - 2; i >= 0; i--) {
        if (i > ctr) {
            Node *tmp;
            if (currId % 2 == 0) {
                tmp = MerkleTree_CreateNewParent(child, NULL, maxDiff);
            } else {
                tmp = MerkleTree_CreateNewParent(NULL, child, maxDiff);
            }
            child = child->parent;
            currId /= 2;
            maxDiff *= 2;
        } else {
            if (id <= curr->midID) {
                MerkleTree_UpdateLeftChild(curr, child);
            } else {
                MerkleTree_UpdateRightChild(curr, child);
            }
            child = child->parent;
            curr = curr->parent;
        }
    }
}

// Assumes that node IDs are consecutive
Node *MerkleTree_CreateTree(uint64_t *ids, uint8_t **values, uint64_t len) {
    Node **leaves = (Node **)malloc(len * sizeof(Node *));
    for (uint64_t i = 0; i < len; i++) {
        leaves[i] = MerkleTree_CreateNewLeaf(ids[i], values[i]);
    }
    printf("Finished creating all leaf nodes\n");
    Node **currNodes = leaves;
    Node **parentNodes;
    uint64_t currLen = max(ceil(len / 2.0), 1);
    uint64_t maxDiff = 2;
    for (int l = 0; l < MAX_TREE_DEPTH; l++) {
        printf("Starting next level with %d nodes\n", currLen);
        parentNodes = (Node **)malloc(currLen * sizeof(Node *));
        for (uint64_t i = 0; i < currLen; i++) {
            if (i % 1000 == 0) printf("Have processed %d/%d nodes in level\n", i, currLen);
            if (2 * i + 1 == currLen) {
                parentNodes[i] = MerkleTree_CreateNewParent(currNodes[2 * i], NULL, maxDiff);
            } else {
                parentNodes[i] = MerkleTree_CreateNewParent(currNodes[2 * i], currNodes[2 * i + 1], maxDiff);
            }
        }
        currLen = max(ceil(currLen / 2.0), 1);
        currNodes = parentNodes;
        maxDiff *= 2;
    }
    return currNodes[0];
}

int MerkleTree_VerifyEmptyProof(Node *head, MerkleProof *proof, uint64_t id) {
    uint8_t buf[SHA256_DIGEST_LENGTH];
    memset(buf, 0, SHA256_DIGEST_LENGTH);
    return MerkleTree_VerifyProof(head, proof, buf, id);
}

int MerkleTree_VerifyProof(Node *head, MerkleProof *proof, uint8_t *value, uint64_t id) {
    int rv;
    EVP_MD_CTX *mdctx;
    uint8_t currHash[SHA256_DIGEST_LENGTH];
    uint8_t nextHash[SHA256_DIGEST_LENGTH];
    uint8_t buf[2 * SHA256_DIGEST_LENGTH];

    mdctx = EVP_MD_CTX_create();
    memcpy(currHash, value, SHA256_DIGEST_LENGTH);

    for (int i = proof->len - 1; i >= 0; i--) {
        CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
        if (id > proof->ids[i]) {
            memcpy(buf, proof->hash[i], SHA256_DIGEST_LENGTH);
            memcpy(buf + SHA256_DIGEST_LENGTH, currHash, SHA256_DIGEST_LENGTH);
        } else {
            memcpy(buf, currHash, SHA256_DIGEST_LENGTH);
            memcpy(buf + SHA256_DIGEST_LENGTH, proof->hash[i], SHA256_DIGEST_LENGTH);
        }
        CHECK_C (EVP_DigestUpdate(mdctx, buf, 2 * SHA256_DIGEST_LENGTH));
        CHECK_C (EVP_DigestUpdate(mdctx, (uint8_t *)&proof->ids[i], sizeof(uint64_t)));
        CHECK_C (EVP_DigestFinal_ex(mdctx, nextHash, NULL));
        memcpy(currHash, nextHash, SHA256_DIGEST_LENGTH);
    }
    if (memcmp(nextHash, head->hash, SHA256_DIGEST_LENGTH) != 0) return ERROR;

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    return rv;
}
