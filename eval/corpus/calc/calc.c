/* A tiny calculator: tokenizer, recursive-descent parser, operator table. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum token_kind {
    TOK_NUM,
    TOK_PLUS,
    TOK_MINUS,
    TOK_STAR,
    TOK_SLASH,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_END,
    TOK_ERROR,
};

struct token {
    enum token_kind kind;
    long value;
};

struct lexer {
    const char *src;
    size_t pos;
    struct token current;
};

typedef long (*binop_fn)(long lhs, long rhs, int *error);

static long op_add(long lhs, long rhs, int *error) { (void)error; return lhs + rhs; }
static long op_sub(long lhs, long rhs, int *error) { (void)error; return lhs - rhs; }
static long op_mul(long lhs, long rhs, int *error) { (void)error; return lhs * rhs; }

static long op_div(long lhs, long rhs, int *error) {
    if (rhs == 0) {
        *error = 1;
        return 0;
    }
    return lhs / rhs;
}

static const binop_fn g_operators[] = {
    [TOK_PLUS] = op_add,
    [TOK_MINUS] = op_sub,
    [TOK_STAR] = op_mul,
    [TOK_SLASH] = op_div,
};

static void lexer_next(struct lexer *lx) {
    while (isspace((unsigned char)lx->src[lx->pos]))
        lx->pos++;
    char c = lx->src[lx->pos];
    if (c == '\0') {
        lx->current.kind = TOK_END;
        return;
    }
    if (isdigit((unsigned char)c)) {
        long value = 0;
        while (isdigit((unsigned char)lx->src[lx->pos]))
            value = value * 10 + (lx->src[lx->pos++] - '0');
        lx->current.kind = TOK_NUM;
        lx->current.value = value;
        return;
    }
    lx->pos++;
    switch (c) {
    case '+': lx->current.kind = TOK_PLUS; break;
    case '-': lx->current.kind = TOK_MINUS; break;
    case '*': lx->current.kind = TOK_STAR; break;
    case '/': lx->current.kind = TOK_SLASH; break;
    case '(': lx->current.kind = TOK_LPAREN; break;
    case ')': lx->current.kind = TOK_RPAREN; break;
    default: lx->current.kind = TOK_ERROR; break;
    }
}

static long parse_expr(struct lexer *lx, int *error);

static long parse_factor(struct lexer *lx, int *error) {
    if (lx->current.kind == TOK_NUM) {
        long value = lx->current.value;
        lexer_next(lx);
        return value;
    }
    if (lx->current.kind == TOK_LPAREN) {
        lexer_next(lx);
        long value = parse_expr(lx, error);
        if (lx->current.kind != TOK_RPAREN)
            *error = 1;
        lexer_next(lx);
        return value;
    }
    if (lx->current.kind == TOK_MINUS) {
        lexer_next(lx);
        return -parse_factor(lx, error);
    }
    *error = 1;
    return 0;
}

static long parse_term(struct lexer *lx, int *error) {
    long value = parse_factor(lx, error);
    while (lx->current.kind == TOK_STAR || lx->current.kind == TOK_SLASH) {
        enum token_kind op = lx->current.kind;
        lexer_next(lx);
        value = g_operators[op](value, parse_factor(lx, error), error);
    }
    return value;
}

static long parse_expr(struct lexer *lx, int *error) {
    long value = parse_term(lx, error);
    while (lx->current.kind == TOK_PLUS || lx->current.kind == TOK_MINUS) {
        enum token_kind op = lx->current.kind;
        lexer_next(lx);
        value = g_operators[op](value, parse_term(lx, error), error);
    }
    return value;
}

int evaluate(const char *text, long *result) {
    struct lexer lx = {text, 0, {TOK_END, 0}};
    int error = 0;
    lexer_next(&lx);
    *result = parse_expr(&lx, &error);
    if (lx.current.kind != TOK_END)
        error = 1;
    return error ? -1 : 0;
}

int main(int argc, char **argv) {
    int failures = 0;
    for (int i = 1; i < argc; i++) {
        long result;
        if (evaluate(argv[i], &result) == 0) {
            printf("%s = %ld\n", argv[i], result);
        } else {
            printf("%s: error\n", argv[i]);
            failures++;
        }
    }
    return failures;
}
