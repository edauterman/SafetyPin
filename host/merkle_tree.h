#ifndef _MERKLE_TREE_H_
#define _MERKLE_TREE_H_

#include <openssl/sha.h>

#define MAX_TREE_DEPTH 35
#define MAX_PROOF_LEVELS MAX_TREE_DEPTH

typedef struct Node Node;

struct Node {
    uint64_t leftID;     // only for internal nodes
    uint64_t rightID;    // only for internal nodes
    uint64_t midID;      // only for internal nodes
    uint64_t id;         // only for leaves 
    uint8_t hash[SHA256_DIGEST_LENGTH];
    Node *rightChild;
    Node *leftChild;
    Node *parent;
};

typedef struct {
    uint8_t head[SHA256_DIGEST_LENGTH];
    uint8_t leaf[SHA256_DIGEST_LENGTH];
    uint8_t hash[MAX_TREE_DEPTH][SHA256_DIGEST_LENGTH];
    uint64_t ids[MAX_TREE_DEPTH];
    uint64_t id;
    int len;
} MerkleProof;

Node *Node_new();
void Node_free(Node *n);

MerkleProof *MerkleProof_new();
void MerkleProof_free(MerkleProof *p);

void MerkleTree_CopyNodeHash(uint8_t *dst, Node *n);
Node *MerkleTree_CreateNewParent(Node *leftChild, Node *rightChild, uint64_t maxDiff);
Node *MerkleTree_CreateNewLeaf(uint64_t id, uint8_t *value);
int MerkleTree_UpdateRightChild(Node *parent, Node *rightChild);
int MerkleTree_UpdateLeftChild(Node *parent, Node *leftChild);
Node *MerkleTree_GetLeafForId(Node *head, uint64_t id);
MerkleProof *MerkleTree_GetProof(Node *head, uint64_t id);
MerkleProof *MerkleTree_GetEmptyProof(Node *head, uint64_t id);
int MerkleTree_InsertLeaf(Node *head, uint64_t id, uint8_t *value);
Node *MerkleTree_CreateTree(uint64_t *ids, uint8_t **values, uint64_t len);
int MerkleTree_VerifyProof(Node *head, MerkleProof *proof, uint8_t *value, uint64_t id);
int MerkleTree_VerifyEmptyProof(Node *head, MerkleProof *proof, uint64_t id);

#endif
