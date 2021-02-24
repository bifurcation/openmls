use crate::{ciphersuite::CryptoError, tree::treemath::TreeMathError};

implement_error! {
    pub enum TreeError {
        Simple {
            InvalidArguments = "Invalid arguments.",
            InvalidUpdatePath = "The computed update path is invalid.",
            InvalidTree = "The tree is not valid.",
            NotAParentNode = "The node is not a parent node.",
        }
        Complex {
            PathSecretDecryptionError(CryptoError) =
                "Error while decrypting `PathSecret`.",
            ParentHashError(ParentHashError) =
                "An error during parent hash computation or validation occurred.",
            TreeMathError(TreeMathError) =
                "Error in a tree math calculation",
        }
    }
}

implement_error! {
    pub enum ParentHashError {
        EndedWithLeafNode = "The search for a valid child ended with a leaf node.",
        AllChecksFailed = "All checks failed: Neither child has the right parent hash.",
        InputNotParentNode = "The input node is not a parent node.",
        NotAParentNode = "The node is not a parent node.",
        EmptyParentNode = "The parent node was blank.",
        ParentHashMissing = "The parent node doesn't have a parent hash set.",
    }
}
