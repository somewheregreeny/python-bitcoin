from ecc import PrivateKey


def solution(board, skill):
    answer = len(board) * len(board[0])

    for info in skill:
        for i in range(info[1], info[3] + 1):
            for j in range(info[2], info[4] + 1):
                signal = False
                if info[0] == 1:
                    if board[i][j] > 0:
                        signal = True
                    board[i][j] -= info[5]
                    if signal and board[i][j] <= 0:
                        answer -= 1
                else:
                    if board[i][j] <= 0:
                        signal = True
                    board[i][j] += info[5]
                    if signal and board[i][j] > 0:
                        answer += 1
    return answer