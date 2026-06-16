from collections import Counter


def input_difference(text1, text2):
    diff = []

    for a, b in zip(text1, text2):
        diff.append(chr(ord(a) ^ ord(b)))

    return diff


def frequency_analysis(data):
    frequency = Counter(data)

    print("\nFrequency Analysis:")
    for item, count in frequency.items():
        print(item, ":", count)


def statistical_bias(data):
    total = len(data)

    zero_count = data.count('0')
    one_count = data.count('1')

    zero_bias = zero_count / total
    one_bias = one_count / total

    print("\nStatistical Bias:");
    print("0 probability:", zero_bias);
    print("1 probability:", one_bias);


# Input
text1 = input("Enter first plaintext: ")
text2 = input("Enter second plaintext: ")

difference = input_difference(text1, text2)

print("\nInput Difference:")
print(difference)

frequency_analysis(text1)

binary_data = ''.join(format(ord(x), '08b') for x in text1)

statistical_bias(binary_data)