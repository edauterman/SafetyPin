#ifndef _MERKLE_TREE_H_
#define _MERKLE_TREE_H_

#include <openssl/sha.h>

#define MAX_TREE_DEPTH 35

typedef struct Node Node;

struct Node {
    int leftID;     // only for internal nodes
    int rightID;    // only for internal nodes
    int midID;      // only for internal nodes
    int id;         // only for leaves 
    uint8_t hash[SHA256_DIGEST_LENGTH];
    Node *rightChild;
    Node *leftChild;
    Node *parent;
};

typedef struct {
    uint8_t hash[MAX_TREE_DEPTH][SHA256_DIGEST_LENGTH];
    bool goRight[MAX_TREE_DEPTH];
    int len;
} MerkleProof;

Node *Node_new();
void Node_free(Node *n);

MerkleProof *MerkleProof_new();
void MerkleProof_free(MerkleProof *p);

Node *MerkleTree_CreateNewParent(Node *rightChild, Node *leftChild);
Node *MerkleTree_CreateNewLeaf(int id, uint8_t *value);
int MerkleTree_UpdateRightChild(Node *parent, Node *rightChild);
int MerkleTree_UpdateLeftChild(Node *parent, Node *leftChild);
Node *MerkleTree_GetLeafForId(Node *head, int id);
MerkleProof *MerkleTree_GetProof(Node *head, int id);
int MerkleTree_InsertLeaf(Node *head, int id, uint8_t *value);
Node *MerkleTree_CreateTree(int *ids, uint8_t **values, int len);

#endif
